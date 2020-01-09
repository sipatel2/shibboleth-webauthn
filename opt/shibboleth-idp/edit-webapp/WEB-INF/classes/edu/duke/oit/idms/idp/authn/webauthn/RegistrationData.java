package edu.duke.oit.idms.idp.authn.webauthn;

import java.util.Date;

import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.exception.Base64UrlException;

/**
 * @author shilen
 */
public class RegistrationData {

  private String credentialTypeString;
  private String credentialIdBase64;
  private String publicKeyCoseBase64;
  private long signatureCount;
  private String attestationTypeString;
  private String netid;
  private String userHandleBase64;
  private Date registrationTime;
  private String nickname;
  
  /**
   * @return the credentialTypeString
   */
  public String getCredentialTypeString() {
    return credentialTypeString;
  }
  
  /**
   * @param credentialTypeString the credentialTypeString to set
   */
  public void setCredentialTypeString(String credentialTypeString) {
    this.credentialTypeString = credentialTypeString;
  }
  
  /**
   * @return the credentialIdBase64
   */
  public String getCredentialIdBase64() {
    return credentialIdBase64;
  }
  
  /**
   * @param credentialIdBase64 the credentialIdBase64 to set
   */
  public void setCredentialIdBase64(String credentialIdBase64) {
    this.credentialIdBase64 = credentialIdBase64;
  }
  
  /**
   * @return the publicKeyCoseBase64
   */
  public String getPublicKeyCoseBase64() {
    return publicKeyCoseBase64;
  }
  
  /**
   * @param publicKeyCoseBase64 the publicKeyCoseBase64 to set
   */
  public void setPublicKeyCoseBase64(String publicKeyCoseBase64) {
    this.publicKeyCoseBase64 = publicKeyCoseBase64;
  }
  
  /**
   * @return the signatureCount
   */
  public long getSignatureCount() {
    return signatureCount;
  }
  
  /**
   * @param signatureCount the signatureCount to set
   */
  public void setSignatureCount(long signatureCount) {
    this.signatureCount = signatureCount;
  }
  
  /**
   * @return the attestationTypeString
   */
  public String getAttestationTypeString() {
    return attestationTypeString;
  }
  
  /**
   * @param attestationTypeString the attestationTypeString to set
   */
  public void setAttestationTypeString(String attestationTypeString) {
    this.attestationTypeString = attestationTypeString;
  }
  
  /**
   * @return the netid
   */
  public String getNetid() {
    return netid;
  }
  
  /**
   * @param netid the netid to set
   */
  public void setNetid(String netid) {
    this.netid = netid;
  }
  
  /**
   * @return the userHandleBase64
   */
  public String getUserHandleBase64() {
    return userHandleBase64;
  }
  
  /**
   * @param userHandleBase64 the userHandleBase64 to set
   */
  public void setUserHandleBase64(String userHandleBase64) {
    this.userHandleBase64 = userHandleBase64;
  }
  
  /**
   * @return the registrationTime
   */
  public Date getRegistrationTime() {
    return registrationTime;
  }
  
  /**
   * @param registrationTime the registrationTime to set
   */
  public void setRegistrationTime(Date registrationTime) {
    this.registrationTime = registrationTime;
  }
  
  /**
   * @return the nickname
   */
  public String getNickname() {
    return nickname;
  }
  
  /**
   * @param nickname the nickname to set
   */
  public void setNickname(String nickname) {
    this.nickname = nickname;
  }
  
  /**
   * @return user handle
   */
  public ByteArray getUserHandle() {
    try {
      return ByteArray.fromBase64Url(this.userHandleBase64);
    } catch (Base64UrlException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * @return public key cose
   */
  public ByteArray getPublicKeyCose() {
    try {
      return ByteArray.fromBase64Url(this.publicKeyCoseBase64);
    } catch (Base64UrlException e) {
      throw new RuntimeException(e);
    }
  }
  
  /**
   * @return user identity
   */
  public UserIdentity getUserIdentity() {
    return UserIdentity.builder()
        .name(this.netid)
        .displayName(this.netid)
        .id(getUserHandle())
        .build();
  }

  /**
   * @return public key credential descriptor
   */
  public PublicKeyCredentialDescriptor getPublicKeyCredentialDescriptor() {
    try {
      return PublicKeyCredentialDescriptor.builder()
          .id(ByteArray.fromBase64Url(credentialIdBase64))
          .build();
    } catch (Base64UrlException e) {
      throw new RuntimeException(e);
    }
  }
  
  /**
   * @return registered credential
   */
  public RegisteredCredential getRegisteredCredential() {
    return RegisteredCredential.builder()
        .credentialId(getPublicKeyCredentialDescriptor().getId())
        .userHandle(getUserHandle())
        .publicKeyCose(getPublicKeyCose())
        .signatureCount(this.getSignatureCount())
        .build();
  }
}
