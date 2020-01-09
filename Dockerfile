FROM tier/shibbidp_configbuilder_container

RUN mkdir -p /webauthn/opt
ADD opt /webauthn/opt
ADD webauthnAndConfigBuilder.sh /tmp

CMD /tmp/webauthnAndConfigBuilder.sh
