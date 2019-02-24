--
-- File generated with SQLiteStudio v3.2.1 on Wed Oct 3 13:24:07 2018
--
-- Text encoding used: System
--
PRAGMA foreign_keys = off;
BEGIN TRANSACTION;

-- Table: certificate
DROP TABLE IF EXISTS certificate;

CREATE TABLE certificate (
    sha_hash CHAR (100) PRIMARY KEY
                        NOT NULL,
    sig_algo INTEGER    NOT NULL,
    issuer   CHAR (300) NOT NULL,
    cn       CHAR (300) NOT NULL
);


-- Table: handshake_extensions
DROP TABLE IF EXISTS handshake_extensions;

CREATE TABLE handshake_extensions (
    id               BIGINT  PRIMARY KEY
                             REFERENCES main (id),
    ems              BOOLEAN,
    alpn             BOOLEAN,
    session_ticket   BOOLEAN,
    npn              BOOLEAN,
    encrypt_then_mac BOOLEAN,
    supported_versions BOOLEAN
);


-- Table: main
DROP TABLE IF EXISTS main;

CREATE TABLE main (
    id               INTEGER    PRIMARY KEY AUTOINCREMENT
                                NOT NULL
                                UNIQUE,
    date             DATETIME   NOT NULL,
    host             CHAR (300) NOT NULL,
    cipher           CHAR (100) NOT NULL,
    tls_version      CHAR (50)  NOT NULL,
    certificate_hash CHAR       REFERENCES certificate (sha_hash) 
);


COMMIT TRANSACTION;
PRAGMA foreign_keys = on;
