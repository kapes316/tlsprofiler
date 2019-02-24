#ifndef OPENSSLCLIENT_H
#define OPENSSLCLIENT_H

#include <iostream>
#include <cstring>
#include <stdint.h>
#include <list>
#include <map>
#include <fstream>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <netinet/in.h>

typedef struct _ext_hdr
{
  uint16_t type;
  uint16_t len;
}ext_hdr;

class OpenSSLClient
{
  public:
    OpenSSLClient();
    OpenSSLClient(const char *host, const char* filename);
    ~OpenSSLClient();

    void     setHost(const char *host);
    void     setTimeout(uint32_t timeout);
    void     setVersionID(const char *versionID);
    uint32_t connect();
    uint32_t secureConnect();
    void     disconnect();

    void     dumpData();
    void     writeJSON();
    uint32_t getServerCertToPEM();

  private:
    void     initSSL();
    void     parseExts();
    void     addExtensions();

    std::list<uint32_t> _exts;
    //hostname:port
    std::string  _host;
    std::string  _filename;
    bool         _connected;
    BIO         *_bio;
    BIO         *_bio_m_cert;
    SSL_CTX     *_ssl_ctx;
    SSL         *_ssl;
    SSL_sh_data *_sh_data;
    SSL_sc_data *_sc_data; //don't need
    uint64_t     _timeout; //in seconds
    std::string  _versionID;
};

#endif
