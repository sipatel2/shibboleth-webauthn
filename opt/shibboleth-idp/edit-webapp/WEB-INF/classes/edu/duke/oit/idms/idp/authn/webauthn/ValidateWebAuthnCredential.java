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

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.RelyingPartyIdentity;

/**
 */
public class ValidateWebAuthnCredential extends AbstractValidationAction {

    /** Default prefix for metrics. */
    @Nonnull @NotEmpty private static final String DEFAULT_METRIC_NAME = "edu.duke.oit.idms.idp.authn.webauthn";
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateWebAuthnCredential.class);

    /** Attempted username. */
    @Nullable @NotEmpty private String username;
    
    private com.fasterxml.jackson.databind.ObjectMapper jsonMapper;

    /** relying party id */
    @NonnullAfterInit @NotEmpty private String relyingPartyId;
    
    /** relying party origin */
    @NonnullAfterInit @NotEmpty private String relyingPartyOrigin;
    
    private RelyingParty rp;

    /** Constructor. */
    public ValidateWebAuthnCredential() {
        setMetricName(DEFAULT_METRIC_NAME);
    }
    
    /**
     * @return relying party id
     */
    @Nonnull @NotEmpty public String getRelyingPartyId() {
        return relyingPartyId;
    }
   
    /**
     * @param id
     */
    public void setRelyingPartyId(@Nonnull @NotEmpty final String id) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
   
        relyingPartyId = Constraint.isNotNull(StringSupport.trimOrNull(id), "Relying party id cannot be null or empty");
    }

    /**
     * @return relying party origin
     */
    @Nonnull @NotEmpty public String getRelyingPartyOrigin() {
        return relyingPartyOrigin;
    }
   
    /**
     * @param origin
     */
    public void setRelyingPartyOrigin(@Nonnull @NotEmpty final String origin) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
   
        relyingPartyOrigin = Constraint.isNotNull(StringSupport.trimOrNull(origin), "Relying party origin cannot be null or empty");
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        if (relyingPartyId == null || relyingPartyOrigin == null) {
          throw new ComponentInitializationException("Relying party id and origin must be set");
        }
        
        jsonMapper = new com.fasterxml.jackson.databind.ObjectMapper()
            .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
            .setSerializationInclusion(Include.NON_ABSENT)
            .registerModule(new Jdk8Module());
        
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
            .id(relyingPartyId)
            .name("Shibboleth Authentication")
            .build();

        rp = RelyingParty.builder()
            .identity(rpIdentity)
            .credentialRepository(RegistrationStorage.getInstance())
            .origins(new HashSet<>(Arrays.asList(new String[] { relyingPartyOrigin })))
            .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
           // .metadataService(Optional.of(metadataService)) // TODO
            .allowUnrequestedExtensions(true)
            .allowUntrustedAttestation(true)
            .validateSignatureCounter(true)
           // .appId(appId)
            .build();
    }
    
    /** {@inheritDoc} */
    @Override protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }

        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return false;
        }
        
        username = request.getParameter("j_username");
        if (username == null || username.isEmpty()) {
            log.warn("{} No username available", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return false;
        }

        return true;
    }

    /** {@inheritDoc} */
    @Override protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        try {
          final HttpServletRequest request = getHttpServletRequest();
          
          String body = request.getParameter("webauthnformdata");

          if (body.contains("\"userHandle\":\"\"")) {
            // https://github.com/Yubico/java-webauthn-server/issues/12
            log.warn("Response contains an empty userHaNdle, removing it.");
            body = body.replaceAll("\"userHandle\":\"\"", "\"userHandle\":null");
          }
        
          AssertionResponse assertionResponse = jsonMapper.readValue(body, AssertionResponse.class);
          AssertionRequest assertionRequest = (AssertionRequest)request.getSession().getAttribute("REQUESTID_" + assertionResponse.getRequestId().getBase64Url());
                  
          if (assertionRequest == null) {
            throw new RuntimeException("Authentication not in progress: " + assertionResponse.getRequestId().getBase64Url());
          }
          
          request.getSession().removeAttribute("REQUESTID_" + assertionResponse.getRequestId().getBase64Url());
          
          if (!assertionRequest.getUsername().isPresent()) {
            throw new RuntimeException("No username??");
          }
          
          // TODO check status of account or ensure webauthn credentials are killed when user leaves?  Duke specific code has been taken out
          
          AssertionResult result = rp.finishAssertion(
              FinishAssertionOptions.builder()
              .request(assertionRequest)
              .response(assertionResponse.getCredential())
              .build());
          
          // core code should do this but just in case...
          if (!assertionResponse.getCredential().getResponse().getParsedAuthenticatorData().getFlags().UV) {
            throw new RuntimeException("No UV flag??");
          }
          
          if (result.isSuccess()) {
            try {
              RegistrationStorage.getInstance().updateSignatureCount(result);
            } catch (Exception e) {
              log.warn("Failed to update signature count for user \"{}\", credential \"{}\"", result.getUsername(), assertionResponse.getCredential().getId(), e);
            }
          } else {
            throw new RuntimeException("WebAuthn authentication error, warnings=" + result.getWarnings());
          }
          
          String webauthnUserName = result.getUsername();
          
          if (!webauthnUserName.equals(assertionRequest.getUsername().get())) {
            throw new RuntimeException("Username mismatch??  webauthnUserName=" + webauthnUserName + ", assertionRequest.getUsername()=" + assertionRequest.getUsername());
          }
          
          if (!webauthnUserName.equals(username)) {
            throw new RuntimeException("Username mismatch??  webauthnUserName=" + webauthnUserName + ", j_username=" + username);
          }
                
          {
            // if i change the username in the db after the assertion is sent, the user ends up authenticating as the original username that isn't in the db anymore
            // not sure if that's a real problem.  doing additional check just in case.  though multiple users can have the same credential id?
            Collection<RegistrationData> allRegistrationsForUser = RegistrationStorage.getInstance().getRegistrationsByUsername(webauthnUserName);
            boolean found = false;
            for (RegistrationData data : allRegistrationsForUser) {
              if (data.getCredentialIdBase64().equals(result.getCredentialId().getBase64Url()) && data.getCredentialIdBase64().equals(assertionResponse.getCredential().getId().getBase64Url()) &&
                  data.getUserHandleBase64().equals(result.getUserHandle().getBase64Url())) {
                found = true;
                break;
              }
            }
            
            if (!found) {
              throw new RuntimeException("Unable to find this registration for this user???  webauthnUserName=" + webauthnUserName);
            }
          }
          
          recordSuccess();
          buildAuthenticationResult(profileRequestContext, authenticationContext);
        } catch (final Exception e) {
          log.error("{} Authentication failure for '{}'", getLogPrefix(), username, e);
          handleError(profileRequestContext, authenticationContext, e, AuthnEventIds.AUTHN_EXCEPTION);
          recordFailure();
        }
    }

    /** {@inheritDoc} */
    @Override @Nonnull protected Subject populateSubject(@Nonnull final Subject subject) {
        subject.getPrincipals().add(new net.shibboleth.idp.authn.principal.UsernamePrincipal(username));

        return subject;
    }
}
