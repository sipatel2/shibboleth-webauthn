package edu.duke.oit.idms.idp.authn.webauthn;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;

/**
 * @author shilen
 */
public class RegistrationResponse {

  private final ByteArray requestId;

  private final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential;

  /**
   * @param requestId
   * @param credential
   */
  public RegistrationResponse(
      @JsonProperty("requestId") ByteArray requestId,
      @JsonProperty("credential") PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential
      ) {
    this.requestId = requestId;
    this.credential = credential;
  }


  /**
   * @return the requestId
   */
  public ByteArray getRequestId() {
    return requestId;
  }


  /**
   * @return the credential
   */
  public PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> getCredential() {
    return credential;
  }
}