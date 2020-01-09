mkdir /output/webauthn
cp -R /webauthn/opt /output/webauthn/
/scriptrun/configBuilder.sh

echo "ADD webauthn/opt/shibboleth-idp/edit-webapp /opt/shibboleth-idp/edit-webapp" >> /output/Dockerfile
echo "ADD webauthn/opt/shibboleth-idp/flows /opt/shibboleth-idp/flows" >> /output/Dockerfile
echo "ADD webauthn/opt/shibboleth-idp/conf /opt/shibboleth-idp/conf" >> /output/Dockerfile
echo "ADD webauthn/opt/shibboleth-idp/views /opt/shibboleth-idp/views" >> /output/Dockerfile

echo "RUN sed -i '/^idp.authn.flows=/ s/=.*/=WebAuthn/' /opt/shibboleth-idp/conf/idp.properties" >> /output/Dockerfile
echo "RUN sed -i '/^idp.additionalProperties=/ s/$/, \/conf\/authn\/WebAuthn.properties/' /opt/shibboleth-idp/conf/idp.properties" >> /output/Dockerfile

echo "RUN rm -f /opt/shibboleth-idp/dist/webapp/WEB-INF/lib/jackson-annotations-2.8.3.jar" >> /output/Dockerfile
echo "RUN rm -f /opt/shibboleth-idp/dist/webapp/WEB-INF/lib/jackson-core-2.8.3.jar" >> /output/Dockerfile
echo "RUN rm -f /opt/shibboleth-idp/dist/webapp/WEB-INF/lib/jackson-databind-2.8.3.jar" >> /output/Dockerfile
echo "RUN cd /opt/shibboleth-idp/edit-webapp/WEB-INF/classes; export CLASSPATH=/opt/shibboleth-idp/dist/webapp/WEB-INF/lib/*:/opt/shibboleth-idp/edit-webapp/WEB-INF/lib/*:/usr/local/tomcat/lib/*; javac edu/duke/oit/idms/idp/authn/webauthn/*.java; cd /opt/shibboleth-idp/bin/; ./build.sh -Didp.target.dir=/opt/shibboleth-idp" >> /output/Dockerfile
