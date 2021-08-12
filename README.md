# shibboleth-webauthn

In progress

Duke University is running a WebAuthn integration with Shibboleth in production.  This git repo is an adjustment to that integration to make it more generic (less Duke specific) and easier to quickly run and demo.

This builds a Shibboleth IdP (v4) using the InCommon Trusted Access Platform container along with its configuration builder and then adds a WebAuthn flow on top of it.

Update the properties in opt/shibboleth-idp/conf/authn/WebAuthn.properties.  
Update LDAP certificate in opt/shibboleth-idp/credentials/ldap-server.crt.  

Build the configuration:

docker build -t my/shibbidp_configbuilder_with_webauthn_container .  
OUTPUTDIR=some-output-directory  
docker run -it -v $OUTPUTDIR:/output -e "BUILD_ENV=LINUX" my/shibbidp_configbuilder_with_webauthn_container  

Build and run the actual IdP:

docker build --rm -t my/shibb-idp-tier $OUTPUTDIR  
docker run -d --name shib-idp -p 443:443 my/shibb-idp-tier  

The WebAuthn registration page would be located at https://localhost/idp/webauthn/registration.  The registration is stored in memory only.  In production, Duke is storing registration data in a database using a modified version of RegistrationStorage.java.

A couple of other items to note.  At Duke, all authentication methods (password, Duo, WebAuthn, social, etc) go through a single flow that decide what should actually be done based on what the user has registered and what the current authentication requirements are.  The flow in this repo just handles WebAuthn and removes the configuration for the standard password flow to make it easier to demo/test.  Also, at Duke, after a successful WebAuthn authentication, the user's username is added to a cookie to allow the user to authenticate next time without having to enter a username.  That functionality has not yet been added here.
