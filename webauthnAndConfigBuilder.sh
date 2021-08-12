mkdir /output/webauthn
cp -R /webauthn/opt /output/webauthn/
/scriptrun/configBuilder.sh

echo "ADD webauthn/opt/shibboleth-idp/edit-webapp /opt/shibboleth-idp/edit-webapp" >> /output/Dockerfile
echo "ADD webauthn/opt/shibboleth-idp/flows /opt/shibboleth-idp/flows" >> /output/Dockerfile
echo "ADD webauthn/opt/shibboleth-idp/conf /opt/shibboleth-idp/conf" >> /output/Dockerfile
echo "ADD webauthn/opt/shibboleth-idp/views /opt/shibboleth-idp/views" >> /output/Dockerfile
echo "ADD webauthn/opt/shibboleth-idp/credentials /opt/shibboleth-idp/credentials" >> /output/Dockerfile

echo "RUN sed -i '/^#idp.authn.flows / s/.*/idp.authn.flows=WebAuthn/' /opt/shibboleth-idp/conf/authn/authn.properties" >> /output/Dockerfile
echo "RUN sed -i '/^idp.additionalProperties=/ s/$/, \/conf\/authn\/WebAuthn.properties/' /opt/shibboleth-idp/conf/idp.properties" >> /output/Dockerfile
echo "RUN sed -i '/ldapURL=/ s/$/ trustFile=\"%{idp.attribute.resolver.LDAP.trustCertificates}\"/' /opt/shibboleth-idp/conf/attribute-resolver.xml" >> /output/Dockerfile

echo "RUN cd /opt/shibboleth-idp/edit-webapp/WEB-INF/classes; export CLASSPATH=/opt/shibboleth-idp/dist/webapp/WEB-INF/lib/*:/opt/shibboleth-idp/edit-webapp/WEB-INF/lib/*:/usr/local/tomcat/lib/*; javac edu/duke/oit/idms/idp/authn/webauthn/*.java; cd /opt/shibboleth-idp/bin/; ./build.sh -Didp.target.dir=/opt/shibboleth-idp" >> /output/Dockerfile
