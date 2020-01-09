# shibboleth-webauthn

In progress

Duke University is running a WebAuthn integration with Shibboleth in production.  This git repo is an adjustment to that integration to make it more generic (less Duke specific) and easier to quickly run and demo.

This builds a Shibboleth IdP using the InCommon Trusted Access Platform container along with its configuration builder and then adds a WebAuthn flow on top of it.

Update the properties in opt/shibboleth-idp/conf/authn/WebAuthn.properties.

docker build -t my/shibbidp_configbuilder_with_webauthn_container .

OUTPUTDIR=some-output-directory

docker run -it -v $OUTPUTDIR:/output -e "BUILD_ENV=LINUX" my/shibbidp_configbuilder_with_webauthn_container

Continue to follow the steps to build and run the actual IdP.

The WebAuthn registration page would be located at https://hostname/idp/webauthn/registration.  The registration is stored in memory only.  In production, Duke is storing registration data in a database using a modified version of RegistrationStorage.java.
