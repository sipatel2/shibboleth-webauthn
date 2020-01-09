package edu.duke.oit.idms.idp.authn.webauthn;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;

/**
 * @author shilen
 */
public class AssertionResponse {

  private final ByteArray requestId;

  private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential;

  /**
   * @param requestId
   * @param credential
   */
  public AssertionResponse(
      @JsonProperty("requestId") ByteArray requestId,
      @JsonProperty("credential") PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential
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
  public PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> getCredential() {
    return credential;
  }
}
