#include "OpenSSLClient.h"
#include <chrono>
#include <unistd.h>
#include "Maps.h"

OpenSSLClient::OpenSSLClient() : _connected(false),
                                 _bio(NULL),
                                 _bio_m_cert(NULL),
                                 _ssl_ctx(NULL),
                                 _ssl(NULL),
                                 _sh_data(NULL),
                                 _sc_data(NULL),
                                 _timeout(5)
{
  initSSL();
}

OpenSSLClient::OpenSSLClient(const char *host, const char* filename) : _connected(false),
                                                 _bio(NULL),
                                                 _bio_m_cert(NULL),
                                                 _ssl_ctx(NULL),
                                                 _ssl(NULL),
                                                 _sh_data(NULL),
                                                 _sc_data(NULL),
                                                 _timeout(5)
{
  initSSL();
  _host = host;
  _filename = filename;
}

OpenSSLClient::~OpenSSLClient()
{
  EVP_cleanup();
  ERR_free_strings();
}

void OpenSSLClient::setHost(const char *host)
{
  _host = host;
}

void OpenSSLClient::setVersionID(const char *versionID)
{
  _versionID = versionID;
}

void OpenSSLClient::initSSL()
{
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
}

uint32_t OpenSSLClient::connect()
{
  if(_bio || _connected)
  {
    return(1);
  }
  std::string host = _host;
  host+=":443";
  _connected = false;
  _bio       = BIO_new_connect(host.c_str());

  if(_bio)
  {
    _connected = true;
    return(0);
  }
  std::cout << "Failed to connect to [" << host << "] " << ERR_reason_error_string(ERR_get_error()) << std::endl; 
  return(1);
}

void OpenSSLClient::setTimeout(uint32_t timeout)
{
  _timeout = timeout;
}

uint32_t OpenSSLClient::secureConnect()
{
  if(_connected || _ssl_ctx || _bio || _ssl)
  {
    return(1);
  }
  std::string host = _host;
  host+=":443";
  _connected = false;
  _ssl_ctx   = SSL_CTX_new(SSLv23_client_method());
  
  if(!_ssl_ctx)
  {
    std::cout << "Failed to create SSL context!" << ERR_reason_error_string(ERR_get_error()) << std::endl; 
    return(1);
  }

  _bio = BIO_new_ssl_connect(_ssl_ctx);
 
  if(!_bio)
  {
    std::cout << "Failed to create BIO context " << ERR_reason_error_string(ERR_get_error()) << std::endl; 
    return(1);
  }

  BIO_get_ssl(_bio, &_ssl);
  SSL_set_mode(_ssl, SSL_MODE_AUTO_RETRY);
  BIO_set_conn_hostname(_bio, host.c_str()); 
  BIO_set_nbio(_bio, 1); //set nonblocking
  addExtensions(); //add additional extensions

  std::chrono::system_clock::time_point start   = std::chrono::system_clock::now();
  std::chrono::duration<double>         seconds;
  while(BIO_do_connect(_bio) <= 0)
  {
    seconds = std::chrono::system_clock::now() - start;
    if((seconds.count() > _timeout)||(!BIO_should_retry(_bio)))
    {
      return(1);
    }
    usleep(100);
  }

  _connected = true;

  SSL_get_server_hello_data(&_sh_data);
  SSL_get_server_cert_data(&_sc_data);
  getServerCertToPEM();
  parseExts();

  return(0);
}

void OpenSSLClient::disconnect()
{
  if(_bio)
  {
    if(BIO_reset(_bio))
      std::cout << "Failed resetting the connection" << std::endl;
    BIO_free(_bio);
  }
  if(_bio_m_cert)
  {
    BIO_free(_bio_m_cert);
  }
  if(_ssl_ctx)
    SSL_CTX_free(_ssl_ctx);
    

  _bio       = NULL;
  _ssl       = NULL;
  _ssl_ctx   = NULL;
  _connected = false;
}

std::string findMap(const std::map<uint32_t,std::string> &map, uint32_t value)
{
  for(auto& iter:map)
  {
    if(iter.first == value)
      return(iter.second);
  }
  return("UNKNOWN");
}

uint32_t OpenSSLClient::getServerCertToPEM()
{
  _bio_m_cert = BIO_new(BIO_s_mem());
  X509 *peer  = SSL_get_peer_certificate(_ssl);
  if (peer != NULL) 
  {
    PEM_write_bio_X509(_bio_m_cert, peer);
  }
  else
  {
    std::cout << "Failed to get the server cert!" << std::endl;
  }

  return(0);
}

void OpenSSLClient::parseExts()
{
  ext_hdr *hdr        = NULL;
  uint32_t bytes_left = _sh_data->extensions_len;

  while(1)
  {
    if((0 == bytes_left) || (bytes_left > 4096))
    {
      break;
    }
    hdr = (ext_hdr*)(_sh_data->extensions + (_sh_data->extensions_len - bytes_left));
    _exts.push_back(ntohs(hdr->type));

    bytes_left -= (sizeof(ext_hdr) + ntohs(hdr->len)); 
  }
}

void OpenSSLClient::dumpData()
{
  uint32_t c  = 0;
  uint32_t cs = ntohs(*reinterpret_cast<uint32_t*>(_sh_data->cipher));

  std::cout << "host        " << _host << std::endl;
  std::cout << "tls version " << findMap(ssl_version_tbl,_sh_data->version) << std::endl;
  std::cout << "tls cipher  " << findMap(ssl_ciphers_tbl,cs) << std::endl;
  std::cout << "tls exts    ";
  for(auto& iter:_exts)
  {
    std::cout << findMap(ssl_exts_tbl,iter);
    if(0 == ++c) std::cout << ",";
  }
  std::cout << std::endl;

  std::cout << "tls exts#   ";
  for(auto& iter:_exts)
  {
    std::cout << iter;
    if(0 == ++c) std::cout << ",";
  }
  std::cout << std::endl;
}

void OpenSSLClient::writeJSON()
{
  std::ofstream   of;
  std::streambuf *buf;
  std::string     fname     = _filename;
  bool            is_stdout = false;

  if(fname.length() > 0)
  {
    of.open(fname.c_str());
    buf = of.rdbuf();
  }
  else
  {
    is_stdout = true;
    buf       = std::cout.rdbuf();
  }

  std::ostream out(buf);

  out << "{" << std::endl;
  out << "    \"versionID\": \"" << _versionID << "\"," << std::endl;
  out << "    \"url\": \"" << _host << "\"," << std::endl;
  if(_connected)
  {
    out << "    \"connectionStatus\": 1" << "," << std::endl;
  }
  else
  {
    out << "    \"connectionStatus\": 0" << std::endl;
  }
  if(!_connected)
  {
    out << "}" << std::endl;
    if(!is_stdout)
    {
      of.close();
    }
    return;
  }
  uint32_t cs = ntohs(*reinterpret_cast<uint32_t*>(_sh_data->cipher));

  out << "    \"negotiatedTLSVersion\": \"" << findMap(ssl_version_tbl,_sh_data->version) << "\"," << std::endl;
  out << "    \"negotiatedCipher\": { \"cipherName\": \"" << findMap(ssl_ciphers_tbl,cs);
  out << "\", \"cipherNumber\": " << cs << " }," << std::endl;

  out << "    \"extensions\": [ ";
  size_t count = 0;
  for(auto& iter:_exts)
  {
    count++;
    out << "{\"extensionName\": \"" << findMap(ssl_exts_tbl,iter) << "\",\"extensionNumber\": " << iter << "}";
    if(count != _exts.size())
    {
      out << ",";
    }
  }
  out << "]," << std::endl;

  out << "    \"serverCertificate\" : [" << std::endl;
  char     *cert     = NULL;
  uint32_t  cert_len = BIO_get_mem_data(_bio_m_cert,&cert);
  uint32_t  line     = 0;
  uint32_t  offset   = 0;

  while(offset < cert_len)
  {
    line = strcspn(cert+offset, "\n");
    out << "        \"";
    for(uint32_t a=0;a<line;a++)
    {
      out << (cert+offset)[a];
    }
    out << "\"";
    if(cert+offset != (strstr(cert+offset, "-----END CERTIFICATE-----")))
      out << ",";
    out << std::endl;
    offset += (line+1);
  }

  out << "    ]" << std::endl;
  out << "}" << std::endl;
  if(!is_stdout)
  {
    of.close();
  }
}

/*
typedef struct tlsextnextprotoctx_st {
    unsigned char *data;
    size_t len;
    int status;
} tlsextnextprotoctx;

static tlsextnextprotoctx next_proto;
static int next_proto_cb(SSL *s, unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
  return(SSL_TLSEXT_ERR_OK);
}
*/
static int ocsp_resp_cb(SSL *s, void *arg)
{
  return(1);
}

static int sct_validation_cb(const CT_POLICY_EVAL_CTX *ctx,
                             const STACK_OF(SCT) *scts, void *arg)
{
  return(1);
}

const uint32_t protos_len         = 12;
const uint8_t  protos[protos_len] = {0x08,0x68,0x74,0x74,0x70,0x2f,0x31,0x2e,0x31,0x02,0x68,0x32};

void OpenSSLClient::addExtensions()
{
  //default extensions are:
  //10 - ec_point_formats
  //11 - elliptic_curves
  //35 - session_ticket
  //22 - encrypt then mac
  //23 - extended master secret
  //13 - signature_algorithms
  //43 - supported_versions  (tls1.3)
  //45 - psk_key_exchange_modes
  //51 - key_share

  //add:
  //0  - server_name
  //16 - application_layer_protocol_negotiation 'http/1.1,h2'
  //5  - ocsp
  //12 - signed_certificate_timestamp

  /* If we send both NPN and ALPN the server will respond with ALPN - ALPN is used by browsers
  next_proto.data   = protos;
  next_proto.len    = protos_len;
  next_proto.status = -1;

  SSL_CTX_set_next_proto_select_cb(_ssl_ctx, next_proto_cb, &next_proto);*/
 
  if(!SSL_set_tlsext_host_name(_ssl, _host.c_str()))
  {
    std::cout << "Failed setting server name extension" << std::endl;
  }

  if(0 != SSL_set_alpn_protos(_ssl, protos, protos_len))
  {
    std::cout << "Failed adding ALPN extension" << std::endl;
  }

  SSL_set_tlsext_status_type(_ssl, TLSEXT_STATUSTYPE_ocsp);
  SSL_CTX_set_tlsext_status_cb(_ssl_ctx, ocsp_resp_cb);

  SSL_set_ct_validation_callback(_ssl, sct_validation_cb, NULL);
}
