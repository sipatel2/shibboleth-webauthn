package edu.duke.oit.idms.idp.authn.webauthn;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;

/**
 * 
 */
public class RegistrationServlet extends HttpServlet {

  private final Logger log = LoggerFactory.getLogger(RegistrationServlet.class);

  private String registrationPage = "/webauthn/webauthn_registration.jsp";
  
  private RelyingParty rp;
  
  private com.fasterxml.jackson.databind.ObjectMapper jsonMapper;
  
  private static final SecureRandom random = new SecureRandom();

  public void init(ServletConfig config) throws ServletException {
    super.init(config);

    Properties prop = new Properties();
    try {
      prop.load(new FileInputStream(new File("/opt/shibboleth-idp/conf/authn/WebAuthn.properties")));
    } catch (Exception e) {
      throw new RuntimeException("Unable to load /opt/shibboleth-idp/conf/authn/WebAuthn.properties", e);
    }
    
    String relyingPartyId = prop.getProperty("idp.WebAuthn.relyingParty.id");
    String relyingPartyOrigin = prop.getProperty("idp.WebAuthn.relyingParty.origin");
    
    if (relyingPartyId == null || relyingPartyOrigin == null) {
      throw new RuntimeException("Relying party id and origin must be set");
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
  
  /**
   * 
   */
  private static final long serialVersionUID = -3390494805921509930L;

  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    redirectToLoginPage(request, response);
  }
  
  protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    
    PrintWriter out = response.getWriter();
    response.setContentType("application/json");
    response.setCharacterEncoding("UTF-8");
    
    if (request.getParameter("type").equals("start")) {
      String username = request.getParameter("username");
      log.info("Add credential request for username=" + username);
      
      String nickname = request.getParameter("credentialNickname");
      
      byte[] newUserHandle = new byte[64];
      random.nextBytes(newUserHandle);
      
      byte[] requestId = new byte[64];
      random.nextBytes(requestId);

      Optional<ByteArray> existingUserHandle = RegistrationStorage.getInstance().getUserHandleForUsername(username);
      
      PublicKeyCredentialCreationOptions registrationRequest = rp.startRegistration(
          StartRegistrationOptions.builder()
          .user(UserIdentity.builder()
              .name(username)
              .displayName(username)
              .id(existingUserHandle.isPresent() ? existingUserHandle.get() : new ByteArray(newUserHandle))
              .build()
              )
          .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
              .requireResidentKey(false)
              .userVerification(UserVerificationRequirement.REQUIRED)
              .build()
              )
          .build());

      Map<String, Object> registrationRequestWrapper = new LinkedHashMap<String, Object>();
      registrationRequestWrapper.put("username", username);
      registrationRequestWrapper.put("credentialNickname", nickname);
      registrationRequestWrapper.put("requestId", new ByteArray(requestId));
      registrationRequestWrapper.put("publicKeyCredentialCreationOptions", registrationRequest);
      
      request.getSession().setAttribute("REQUESTID_" + new ByteArray(requestId).getBase64Url(), registrationRequestWrapper);
      
      String json = jsonMapper.writeValueAsString(registrationRequestWrapper);

      log.info("Add credential request for username=" + username + ", success=" + json);
      String finalJson = "{\"success\":true,\"request\":" + json + "}";
      out.print(finalJson);
      out.flush();
    } else if (request.getParameter("type").equals("finish")) {
      StringBuffer buffer = new StringBuffer();
      String line = null;
      try {
        BufferedReader reader = request.getReader();
        while ((line = reader.readLine()) != null) {
          buffer.append(line);
        }
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
      
      String incomingJson = buffer.toString();

      try {
        RegistrationResponse registrationResponse = jsonMapper.readValue(incomingJson, RegistrationResponse.class);

        @SuppressWarnings("unchecked")
        Map<String, Object> registrationRequestWrapper = (Map<String, Object>)request.getSession().getAttribute("REQUESTID_" + registrationResponse.getRequestId().getBase64Url());
                
        if (registrationRequestWrapper == null) {
          throw new RuntimeException("Registration not in progress: " + registrationResponse.getRequestId().getBase64Url());
        }

        String username = (String)registrationRequestWrapper.get("username");
        log.info("Add credential finish for username=" + username);
        
        request.getSession().removeAttribute("REQUESTID_" + registrationResponse.getRequestId().getBase64Url());
        
        PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = (PublicKeyCredentialCreationOptions)registrationRequestWrapper.get("publicKeyCredentialCreationOptions");
        String credentialNickname = (String)registrationRequestWrapper.get("credentialNickname");
        
        RegistrationResult registration = rp.finishRegistration(
            FinishRegistrationOptions.builder()
            .request(publicKeyCredentialCreationOptions)
            .response(registrationResponse.getCredential())
            .build());

        RegistrationStorage.getInstance().addRegistration(username, registration, publicKeyCredentialCreationOptions.getUser(), registrationResponse.getCredential().getResponse(), credentialNickname, incomingJson);
        
        log.info("Add credential finish for username=" + username + ", credentialNickname=" + credentialNickname);
        
        // TODO send an email to the user
        
        String finalJson = "{\"success\":true}";
        out.print(finalJson);
        out.flush();        
      } catch (Exception e) {
        response.setStatus(400);
        
        log.error("Add credential finish failed with failure=" + e.getMessage(), e);
        String finalJson = "{\"success\":false}";
        out.print(finalJson);
        out.flush();
      }
    } else if (request.getParameter("type").equals("authstart")) {
      String uid = request.getParameter("username").trim();
      log.info("WebAuthn authentication start request for uid=" + uid);
      
      byte[] requestId = new byte[64];
      random.nextBytes(requestId);

      AssertionRequest assertionRequest = rp.startAssertion(
          StartAssertionOptions.builder()
          .username(uid)
          .userVerification(UserVerificationRequirement.REQUIRED)
          .build());
      
      Map<String, Object> assertionRequestWrapper = new LinkedHashMap<String, Object>();
      assertionRequestWrapper.put("username", uid);
      assertionRequestWrapper.put("requestId", new ByteArray(requestId));
      assertionRequestWrapper.put("publicKeyCredentialRequestOptions", assertionRequest.getPublicKeyCredentialRequestOptions());
      
      request.getSession().setAttribute("REQUESTID_" + new ByteArray(requestId).getBase64Url(), assertionRequest);
      
      String json = jsonMapper.writeValueAsString(assertionRequestWrapper);
      
      log.info("WebAuthn authentication start request for uid=" + uid + ", success=" + json);
      String finalJson = "{\"success\":true,\"request\":" + json + "}";
      out.print(finalJson);
      out.flush();
    } else {
      throw new RuntimeException("Unexpected");
    }
  }
  
  protected void redirectToLoginPage(HttpServletRequest request, HttpServletResponse response) {
    try {
      request.getRequestDispatcher(registrationPage).forward(request, response);
    } catch (IOException ex) {
      log.error("IP_address=" + request.getRemoteAddr() + ", Unable to display registration page: " + registrationPage, ex);
    } catch (ServletException ex) {
      log.error("IP_address=" + request.getRemoteAddr() + ", Unable to display registration page: " + registrationPage, ex);
    }
  }
}
