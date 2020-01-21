CREATE TABLE "SHIBBOLETH"."WEBAUTHN_USERS" (	
	"NETID" VARCHAR2(32 BYTE) NOT NULL ENABLE, 
	"USER_HANDLE" VARCHAR2(128 BYTE) NOT NULL ENABLE, 
	"LAST_AUTHN_TIME" DATE, 
	 CONSTRAINT "WEBAUTHN_USERS_PK" PRIMARY KEY ("USER_HANDLE"));

CREATE UNIQUE INDEX "SHIBBOLETH"."WEBAUTHN_USERS_NETID_IDX" ON "SHIBBOLETH"."WEBAUTHN_USERS" ("NETID");

CREATE TABLE "SHIBBOLETH"."WEBAUTHN_REGISTRATIONS" (
	"USER_HANDLE" VARCHAR2(128 BYTE) NOT NULL ENABLE, 
	"CREDENTIAL_TYPE" VARCHAR2(20 BYTE) NOT NULL ENABLE, 
	"CREDENTIAL_ID" VARCHAR2(256 BYTE) NOT NULL ENABLE, 
	"PUBLIC_KEY_COSE" VARCHAR2(1024 BYTE) NOT NULL ENABLE, 
	"SIGNATURE_COUNT" NUMBER NOT NULL ENABLE, 
	"ATTESTATION_TYPE" VARCHAR2(32 BYTE) NOT NULL ENABLE, 
	"ATTESTATION_DATA" VARCHAR2(4000 BYTE), 
	"REGISTRATION_TIME" DATE NOT NULL ENABLE, 
	"NICKNAME" VARCHAR2(64 BYTE) NOT NULL ENABLE, 
	"REGISTRATION_RESPONSE" CLOB NOT NULL ENABLE, 
	"LAST_AUTHN_TIME" DATE, 
	 CONSTRAINT "FK_WEBAUTHN_USERS" FOREIGN KEY ("USER_HANDLE")
	  REFERENCES "SHIBBOLETH"."WEBAUTHN_USERS" ("USER_HANDLE") ENABLE);

CREATE INDEX "SHIBBOLETH"."WEBAUTHN_REG_CRED_ID_IDX" ON "SHIBBOLETH"."WEBAUTHN_REGISTRATIONS" ("CREDENTIAL_ID");

CREATE UNIQUE INDEX "SHIBBOLETH"."WEBAUTHN_REG_UNIQ_IDX" ON "SHIBBOLETH"."WEBAUTHN_REGISTRATIONS" ("USER_HANDLE", "CREDENTIAL_ID");

CREATE OR REPLACE EDITIONABLE TRIGGER "SHIBBOLETH"."TRG_WEBAUTHN_LAST_AUTHN" 
BEFORE UPDATE OF signature_count ON webauthn_registrations
FOR EACH ROW
BEGIN
    UPDATE webauthn_users SET last_authn_time = systimestamp WHERE user_handle = :new.user_handle;
    :new.last_authn_time := systimestamp;
END;
/
ALTER TRIGGER "SHIBBOLETH"."TRG_WEBAUTHN_LAST_AUTHN" ENABLE;