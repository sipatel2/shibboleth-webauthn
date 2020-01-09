# shibboleth-webauthn

In progress

This builds a Shibboleth IdP using the InCommon Trusted Access Platform container along with its configuration builder and then adds a WebAuthn flow on top of it.

Update the properties in opt/shibboleth-idp/conf/authn/WebAuthn.properties.

docker build -t my/shibbidp_configbuilder_with_webauthn_container .

OUTPUTDIR=some-output-directory

docker run -it -v $OUTPUTDIR:/output -e "BUILD_ENV=LINUX" my/shibbidp_configbuilder_with_webauthn_container

Continue to follow the steps to build and run the actual IdP.
