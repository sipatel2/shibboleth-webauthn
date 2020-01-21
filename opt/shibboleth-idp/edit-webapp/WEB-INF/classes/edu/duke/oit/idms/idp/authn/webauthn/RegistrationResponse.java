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
