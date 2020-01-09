package edu.duke.oit.idms.idp.authn.webauthn;

import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserIdentity;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author shilen
 */
public class RegistrationStorage implements CredentialRepository {

  private Logger logger = LoggerFactory.getLogger(RegistrationStorage.class);
  
  private Set<RegistrationData> storage = Collections.synchronizedSet(new HashSet<RegistrationData>());


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
  
  private static RegistrationStorage instance = null;
  
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

    RegistrationData data = new RegistrationData();
    data.setAttestationTypeString(registration.getAttestationType().name());
    data.setCredentialIdBase64(registration.getKeyId().getId().getBase64Url());
    data.setCredentialTypeString(registration.getKeyId().getType().name());
    data.setNetid(username);
    data.setNickname(nickname);
    data.setPublicKeyCoseBase64(registration.getPublicKeyCose().getBase64Url());
    data.setUserHandleBase64(userIdentity.getId().getBase64Url());
    data.setSignatureCount(signatureCounter);

    synchronized (storage) {
      storage.add(data);
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

  /**
   * @param username
   * @return collection
   */
  public Collection<RegistrationData> getRegistrationsByUsername(String username) {
    logger.info("Called getRegistrationsByUsername, username=" + username);
    if (username == null || username.isEmpty()) {
      throw new RuntimeException("No username");
    }
    
    Set<RegistrationData> registrations = new LinkedHashSet<RegistrationData>();
    synchronized (storage) {
      for (RegistrationData registration : storage) {
        if (registration.getNetid().equals(username)) {
          registrations.add(registration);
        }
      }
    }
    
    return registrations;
  }

  @Override
  public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
    logger.info("Called getUsernameForUserHandle, userHandle=" + userHandle);

    if (userHandle == null) {
      logger.error("No userHandle");
      throw new RuntimeException("No userHandle");
    }
    
    synchronized (storage) {
      for (RegistrationData registration : storage) {
        if (registration.getUserHandleBase64().equals(userHandle.getBase64Url())) {
          return Optional.of(registration.getNetid());
        }
      }
    }
    
    return Optional.empty();
  }

  @Override
  public Optional<ByteArray> getUserHandleForUsername(String username) {
    logger.info("Called getUserHandleForUsername, username=" + username);

    if (username == null || username.isEmpty()) {
      logger.error("No username");
      throw new RuntimeException("No username");
    }
    
    synchronized (storage) {
      for (RegistrationData registration : storage) {
        if (username.equals(registration.getNetid())) {
          return Optional.of(registration.getUserHandle());
        }
      }
    }
    
    return Optional.empty();
  }

  /**
   * @param result
   */
  public void updateSignatureCount(AssertionResult result) {

    if (result == null) {
      throw new RuntimeException("No result");
    }
    
    logger.info("Called updateSignatureCount, result=" + result + ", netid=" + result.getUsername() + ", credentialId=" + result.getCredentialId().getBase64Url());    

    synchronized (storage) {
      boolean found = false;
      for (RegistrationData registration : storage) {
        if (registration.getUserHandleBase64().equals(result.getUserHandle().getBase64Url()) && registration.getCredentialIdBase64().equals(result.getCredentialId().getBase64Url())) {
          found = true;
          registration.setSignatureCount(result.getSignatureCount());
          break;
        }
      }
      
      if (!found) {
        throw new RuntimeException("No rows updated, credential not registered to user?? result=" + result + ", netid=" + result.getUsername() + ", credentialId=" + result.getCredentialId().getBase64Url());
      }
    }

    logger.info("Updating signature count to " + result.getSignatureCount() + " for netid=" + result.getUsername() + ", credentialId=" + result.getCredentialId().getBase64Url());  
  }

  @Override
  public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
    logger.info("Called lookup, credentialId=" + credentialId + ", userHandle=" + userHandle);
    Set<RegisteredCredential> credentials = lookupAll(credentialId);

    for (RegisteredCredential credential : credentials) {
      if (userHandle != null && userHandle.getBase64Url() != null && !userHandle.getBase64Url().isEmpty() && !userHandle.getBase64Url().equals(credential.getUserHandle().getBase64Url())) {
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

    if (credentialId == null) {
      throw new RuntimeException("No credentialId");
    }
    
    Set<RegistrationData> registrations = new LinkedHashSet<RegistrationData>();
    synchronized (storage) {
      for (RegistrationData registration : storage) {
        if (registration.getCredentialIdBase64().equals(credentialId.getBase64Url())) {
          registrations.add(registration);
        }
      }
    }
    
    Set<RegisteredCredential> registeredCredentials = new LinkedHashSet<RegisteredCredential>();
    for (RegistrationData registration : registrations) {
      RegisteredCredential registeredCredential = registration.getRegisteredCredential();
      
      registeredCredentials.add(registeredCredential);
    }

    logger.info("Called lookupAll, credentialId=" + credentialId + ", returning " + registeredCredentials.size() + " results");
    return Collections.unmodifiableSet(registeredCredentials);
  }
}
