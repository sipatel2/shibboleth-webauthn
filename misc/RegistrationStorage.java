/**
 * Copyright 2019 Duke University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package edu.duke.oit.idms.idp.authn.webauthn;

import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;

import edu.duke.oit.idms.idp.authn.dbconn.DatabaseConnectionFactory;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

/**
 * @author shilen
 */
public class RegistrationStorage implements CredentialRepository {

  private Logger logger = LoggerFactory.getLogger(RegistrationStorage.class);

  /**
   * @return instance
   */
  public synchronized static RegistrationStorage getInstance() {
    if (instance == null) {
      try {
        instance = new RegistrationStorage();
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    return instance;
  }
  
  private RegistrationStorage() {
    Thread registeredUsersThread = new Thread(new Runnable() {
      public void run() {
        while (true) {
          Connection conn = null;
          PreparedStatement ps = null;
          ResultSet rs = null;
          
          Set<String> actualUsers = new HashSet<String>();
          try {
            conn = DatabaseConnectionFactory.getShibbolethDatabaseConnection();
            String sql = "select netid from webauthn_users";
            ps = conn.prepareStatement(sql);
            rs = ps.executeQuery();
            
            while (rs.next()) {
              String netid = rs.getString("netid");
              actualUsers.add(netid);
              
              if (!registeredUsers.contains(netid)) {
                registeredUsers.add(netid);
              }
            }
            
            for (String netid : new HashSet<String>(registeredUsers)) {
              if (!actualUsers.contains(netid)) {
                registeredUsers.remove(netid);
              }
            }
            
            logger.info("Current registered users: " + String.join(",", registeredUsers));
          } catch (Exception e) {
            logger.error("Error looking for registered users", e);
          } finally {
            if (rs != null) {
              try {
                rs.close();
              } catch (SQLException e) {
                // ignore
              }
            }

            if (ps != null) {
              try {
                ps.close();
              } catch (SQLException e) {
                // ignore
              }
            }
            
            if (conn != null) {
              try {
                conn.close();
              } catch (SQLException e) {
                // ignore
              }
            }
            
            try {
              Thread.sleep(60000);
            } catch (InterruptedException e) {
              // ignore
            }
          }
        }
      }
    });
    
    registeredUsersThread.start();
  }
  
  private static RegistrationStorage instance = null;
  
  private Set<String> registeredUsers = Collections.synchronizedSet(new HashSet<String>());

  /**
   * @param username
   * @param registration 
   * @param userIdentity 
   * @param authenticatorAttestationResponse 
   * @param nickname 
   * @param registrationResponse 
   */
  public void addRegistration(String username, RegistrationResult registration, UserIdentity userIdentity, AuthenticatorAttestationResponse authenticatorAttestationResponse, String nickname, String registrationResponse) {
    long signatureCounter = authenticatorAttestationResponse.getAttestation().getAuthenticatorData().getSignatureCounter();
    logger.info("Called addRegistration, username=" + username + ", registration=" + registration + ", userIdentity=" + userIdentity + ", signatureCounter=" + signatureCounter + ", nickname=" + nickname);
    
    if (!userIdentity.getName().equals(username)) {
      throw new RuntimeException("Username mismatch, userIdentity.getName()=" + userIdentity.getName() + ", username=" + username);
    }

    Optional<ByteArray> userHandle = getUserHandleForUsername(username);
    
    String aaguid = null;
    
    try {
      aaguid = authenticatorAttestationResponse.getParsedAuthenticatorData().getAttestedCredentialData().get().getAaguid().getHex().replaceFirst("(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)", "$1-$2-$3-$4-$5");
    } catch (Exception e) {
      // ignore for now
      logger.error("Failed to parse aaguid", e);
    }
    
    Connection conn = null;
    PreparedStatement ps1 = null;
    PreparedStatement ps2 = null;

    try {
      conn = DatabaseConnectionFactory.getShibbolethDatabaseConnection();
      if (!userHandle.isPresent()) {
        // need to insert new user
        String sql = "insert into webauthn_users (netid, user_handle) values (?, ?)";
        ps1 = conn.prepareStatement(sql);
        ps1.setString(1, username.trim());
        ps1.setString(2, userIdentity.getId().getBase64Url());
        ps1.executeUpdate();
      } else {

        // verify that the user handle matches
        if (!userHandle.get().getBase64Url().equals(userIdentity.getId().getBase64Url())) {
          throw new RuntimeException("User handle mismatch, userHandle1=" + userHandle.get().getBase64Url() + ", userHandle2=" + userIdentity.getId().getBase64Url());
        }
      }
      
      String sql = "insert into webauthn_registrations (user_handle, credential_type, credential_id, public_key_cose, signature_count, attestation_type, attestation_data, registration_time, nickname, registration_response) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
      ps2 = conn.prepareStatement(sql);
      ps2.setString(1, userIdentity.getId().getBase64Url());
      ps2.setString(2, registration.getKeyId().getType().name());
      ps2.setString(3, registration.getKeyId().getId().getBase64Url());
      ps2.setString(4, registration.getPublicKeyCose().getBase64Url());
      ps2.setLong(5, signatureCounter);
      ps2.setString(6, registration.getAttestationType().name());
      ps2.setString(7, aaguid);
      ps2.setTimestamp(8, new Timestamp(System.currentTimeMillis()));
      ps2.setString(9, nickname);
      ps2.setString(10, registrationResponse);
      ps2.executeUpdate();
      conn.commit();
      
      logger.info("Added registration, username=" + username + ", registration=" + registration + ", userIdentity=" + userIdentity + ", signatureCounter=" + signatureCounter + ", nickname=" + nickname);
    } catch (Exception e) {
      try {
        conn.rollback();
      } catch (SQLException e1) {
        // ignore
      }
      logger.info("Error in addRegistration, username=" + username + ", registration=" + registration + ", userIdentity=" + userIdentity + ", signatureCounter=" + signatureCounter + ", nickname=" + nickname);
      throw new RuntimeException(e);
    } finally {

      if (ps1 != null) {
        try {
          ps1.close();
        } catch (SQLException e) {
          // ignore
        }
      }
      
      if (ps2 != null) {
        try {
          ps2.close();
        } catch (SQLException e) {
          // ignore
        }
      }
      
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException e) {
          // ignore
        }
      }
    }    
  }

  @Override
  public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
    logger.info("Called getCredentialIdsForUsername, username=" + username);

    Set<PublicKeyCredentialDescriptor> credentialIds = new LinkedHashSet<PublicKeyCredentialDescriptor>();
    
    Collection<RegistrationData> registrations = getRegistrationsByUsername(username);
    for (RegistrationData registration : registrations) {
      credentialIds.add(registration.getPublicKeyCredentialDescriptor());
    }
    
    logger.info("Called getCredentialIdsForUsername, username=" + username + ", returning " + credentialIds.size() + " results");

    return credentialIds;
  }
  
  private Collection<RegistrationData> internal_getRegistrationsFromResultSet(ResultSet rs) throws SQLException, Base64UrlException {

    Collection<RegistrationData> registrations = new ArrayList<RegistrationData>();

    while (rs.next()) {
      String credentialTypeString = rs.getString("credential_type");
      String credentialIdBase64 = rs.getString("credential_id");
      String publicKeyCoseBase64 = rs.getString("public_key_cose");
      long signatureCount = rs.getLong("signature_count");
      String attestationTypeString = rs.getString("attestation_type");
      String netid = rs.getString("netid");
      String userHandleBase64 = rs.getString("user_handle");
      Date registrationTime = new Date(rs.getTimestamp("registration_time").getTime());
      String nickname = rs.getString("nickname");
      
      AttestationType attestationType = AttestationType.valueOf(attestationTypeString);
      if (attestationType == null) {
        throw new RuntimeException("Invalid attestation type: " + attestationTypeString);
      }
      
      PublicKeyCredentialType credentialType = PublicKeyCredentialType.valueOf(credentialTypeString);
      if (credentialType == null) {
        throw new RuntimeException("Invalid credential type type: " + credentialTypeString);
      }
      
      RegistrationData registration = new RegistrationData();
      registration.setAttestationTypeString(attestationTypeString);
      registration.setCredentialIdBase64(credentialIdBase64);
      registration.setCredentialTypeString(credentialTypeString);
      registration.setNetid(netid);
      registration.setNickname(nickname);
      registration.setPublicKeyCoseBase64(publicKeyCoseBase64);
      registration.setRegistrationTime(registrationTime);
      registration.setSignatureCount(signatureCount);
      registration.setUserHandleBase64(userHandleBase64);
      
      registrations.add(registration);
    }
    
    return registrations;
  }

  /**
   * @param username
   * @return collection
   */
  public Collection<RegistrationData> getRegistrationsByUsername(String username) {
    logger.info("Called getRegistrationsByUsername, username=" + username);
    if (StringUtils.isEmpty(username)) {
      throw new RuntimeException("No username");
    }
    
    Connection conn = null;
    PreparedStatement ps = null;
    ResultSet rs = null;
        
    try {
      conn = DatabaseConnectionFactory.getShibbolethDatabaseConnection();
      
      String sql = "select netid, user_handle, credential_type, credential_id, public_key_cose, signature_count, attestation_type, registration_time, nickname from webauthn_registrations_v where netid = ?";
      ps = conn.prepareStatement(sql);
      ps.setString(1, username);
      rs = ps.executeQuery();
      
      Collection<RegistrationData> registrations = internal_getRegistrationsFromResultSet(rs);
      logger.info("Called getRegistrationsByUsername, username=" + username + ", returning " + registrations.size() + " results");
      return registrations;
    } catch (SQLException | Base64UrlException e) {
      logger.error("Error in getRegistrationsByUsername, username=" + username, e);
      throw new RuntimeException(e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException e) {
          // ignore
        }
      }

      if (ps != null) {
        try {
          ps.close();
        } catch (SQLException e) {
          // ignore
        }
      }
      
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException e) {
          // ignore
        }
      }
    }
  }

  @Override
  public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
    logger.info("Called getUsernameForUserHandle, userHandle=" + userHandle);

    Connection conn = null;
    PreparedStatement ps = null;
    ResultSet rs = null;

    if (userHandle == null) {
      logger.error("No userHandle");
      throw new RuntimeException("No userHandle");
    }
    
    try {
      conn = DatabaseConnectionFactory.getShibbolethDatabaseConnection();
      String userHandleBase64 = userHandle.getBase64Url();
      String sql = "select netid from webauthn_users where user_handle = ?";
      ps = conn.prepareStatement(sql);
      ps.setString(1, userHandleBase64);
      rs = ps.executeQuery();
      
      if (rs.next()) {
        String netid = rs.getString("netid");
        logger.info("Called getUsernameForUserHandle, userHandle=" + userHandle + ", returning NetID=" + netid);
        return Optional.of(netid);
      } else {
        logger.info("Called getUsernameForUserHandle, userHandle=" + userHandle + ", returning no NetID");
        return Optional.empty();
      }
    } catch (SQLException e) {
      logger.error("Error in getUsernameForUserHandle, userHandle=" + userHandle, e);
      throw new RuntimeException(e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException e) {
          // ignore
        }
      }

      if (ps != null) {
        try {
          ps.close();
        } catch (SQLException e) {
          // ignore
        }
      }
      
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException e) {
          // ignore
        }
      }
    }
  }

  @Override
  public Optional<ByteArray> getUserHandleForUsername(String username) {
    logger.info("Called getUserHandleForUsername, username=" + username);

    Connection conn = null;
    PreparedStatement ps = null;
    ResultSet rs = null;

    if (StringUtils.isEmpty(username)) {
      logger.error("No username");
      throw new RuntimeException("No username");
    }
    
    try {
      conn = DatabaseConnectionFactory.getShibbolethDatabaseConnection();
      String sql = "select user_handle from webauthn_users where netid = ?";
      ps = conn.prepareStatement(sql);
      ps.setString(1, username);
      rs = ps.executeQuery();
      
      if (rs.next()) {
        String userHandleBase64 = rs.getString("user_handle");
        ByteArray userHandle = ByteArray.fromBase64Url(userHandleBase64);
        logger.info("Called getUserHandleForUsername, username=" + username + ", returning userHandle=" + userHandle.getBase64Url());
        return Optional.of(userHandle);
      } else {
        logger.info("Called getUserHandleForUsername, username=" + username + ", returning no userHandle");
        return Optional.empty();
      }
    } catch (SQLException | Base64UrlException e) {
      logger.error("Error in getUserHandleForUsername, username=" + username, e);
      throw new RuntimeException(e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException e) {
          // ignore
        }
      }

      if (ps != null) {
        try {
          ps.close();
        } catch (SQLException e) {
          // ignore
        }
      }
      
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException e) {
          // ignore
        }
      }
    }
  }

  /**
   * @param result
   */
  public void updateSignatureCount(AssertionResult result) {

    if (result == null) {
      throw new RuntimeException("No result");
    }
    
    logger.info("Called updateSignatureCount, result=" + result + ", netid=" + result.getUsername() + ", credentialId=" + result.getCredentialId().getBase64Url());    

    Connection conn = null;
    PreparedStatement ps = null;

    try {
      conn = DatabaseConnectionFactory.getShibbolethDatabaseConnection();
      String sql = "update webauthn_registrations set signature_count = ? where user_handle = ? and credential_id = ?";
      ps = conn.prepareStatement(sql);
      ps.setLong(1, result.getSignatureCount());
      ps.setString(2, result.getUserHandle().getBase64Url());
      ps.setString(3, result.getCredentialId().getBase64Url());
      
      int count = ps.executeUpdate();
      if (count != 1) {
        throw new RuntimeException("No rows updated, credential not registered to user?? result=" + result + ", netid=" + result.getUsername() + ", credentialId=" + result.getCredentialId().getBase64Url());
      }
      
      conn.commit();
      
    } catch (SQLException e) {
      try {
        conn.rollback();
      } catch (SQLException e1) {
        // ignore
      }
      
      logger.error("Error in updateSignatureCount, result=" + result + ", netid=" + result.getUsername() + ", credentialId=" + result.getCredentialId().getBase64Url(), e);
      throw new RuntimeException(e);
    } finally {

      if (ps != null) {
        try {
          ps.close();
        } catch (SQLException e) {
          // ignore
        }
      }
      
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException e) {
          // ignore
        }
      }
    }

    logger.info("Updating signature count to " + result.getSignatureCount() + " for netid=" + result.getUsername() + ", credentialId=" + result.getCredentialId().getBase64Url());  
  }

  @Override
  public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
    logger.info("Called lookup, credentialId=" + credentialId + ", userHandle=" + userHandle);
    Set<RegisteredCredential> credentials = lookupAll(credentialId);

    for (RegisteredCredential credential : credentials) {
      if (userHandle != null && !StringUtils.isEmpty(userHandle.getBase64Url()) && !userHandle.getBase64Url().equals(credential.getUserHandle().getBase64Url())) {
        continue;
      }
      
      logger.info("Called lookup, credentialId=" + credentialId + ", userHandle=" + userHandle + ", returning 1 result");
      return Optional.of(credential);
    }
    
    logger.info("Called lookup, credentialId=" + credentialId + ", userHandle=" + userHandle + ", returning 0 results");
    return Optional.empty();
  }

  @Override
  public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
    logger.info("Called lookupAll, credentialId=" + credentialId);
    
    Connection conn = null;
    PreparedStatement ps = null;
    ResultSet rs = null;

    if (credentialId == null) {
      throw new RuntimeException("No credentialId");
    }
        
    try {
      conn = DatabaseConnectionFactory.getShibbolethDatabaseConnection();
      
      String credentialIdBase64 = credentialId.getBase64Url();
      String sql = "select netid, user_handle, credential_type, credential_id, public_key_cose, signature_count, attestation_type, registration_time, nickname from webauthn_registrations_v where credential_id = ?";
      ps = conn.prepareStatement(sql);
      ps.setString(1, credentialIdBase64);
      rs = ps.executeQuery();
      
      Collection<RegistrationData> registrations = internal_getRegistrationsFromResultSet(rs);
      Set<RegisteredCredential> registeredCredentials = new LinkedHashSet<RegisteredCredential>();
      for (RegistrationData registration : registrations) {
        RegisteredCredential registeredCredential = registration.getRegisteredCredential();
        
        registeredCredentials.add(registeredCredential);
      }

      logger.info("Called lookupAll, credentialId=" + credentialId + ", returning " + registeredCredentials.size() + " results");
      return Collections.unmodifiableSet(registeredCredentials);
    } catch (SQLException | Base64UrlException e) {
      logger.error("Error in lookupAll, credentialId=" + credentialId, e);
      throw new RuntimeException(e);
    } finally {
      if (rs != null) {
        try {
          rs.close();
        } catch (SQLException e) {
          // ignore
        }
      }

      if (ps != null) {
        try {
          ps.close();
        } catch (SQLException e) {
          // ignore
        }
      }
      
      if (conn != null) {
        try {
          conn.close();
        } catch (SQLException e) {
          // ignore
        }
      }
    }
  }
  
  /**
   * @param netid
   * @return boolean
   */
  public boolean hasRegistered(String netid) {
    if (StringUtils.isEmpty(netid)) {
      return false;
    }
    
    return registeredUsers.contains(netid);
  }
}
