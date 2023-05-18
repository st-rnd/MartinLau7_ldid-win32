//
//  certhandler.cpp
//
//
//  Created by MartinLau on 04/03/2021.
//

#include "libmagicsignature.h"

#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <string.h>
#include <sys/time.h>
#include <unistd.h> // for select
// #include <sys/stat.h>

#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include <openssl/crypto.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

// MARK: - Helper

bool is_G3_CN(X509 *cert) {
  // 0x817d2f7a old CN
  unsigned long issuerHash = X509_issuer_name_hash(cert);
  if (0x9b16b75c == issuerHash) {
    return true;
  } else {
    return false;
  }
}

char *ASN1_TIME2tring(const ASN1_TIME *time) {
  BIO *out = BIO_new(BIO_s_mem());
  if (!out) {
    return NULL;
  }

  ASN1_TIME_print(out, time);
  BUF_MEM *bptr = NULL;
  BIO_get_mem_ptr(out, &bptr);
  if (!bptr) {
    return NULL;
  }
  std::string name_str(bptr->data, bptr->length);
  char *val = strdup(name_str.c_str());
  return val;
}

// MARK: - request & response

// int prepareRequest(OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md,
//                    X509 *issuer, STACK_OF(OCSP_CERTID) * ids) {
//   OCSP_CERTID *id;
//   if (!issuer) {
//     printf("%s", "No issuer certificate specified");
//     // BIO_printf(bio_err, "No issuer certificate specified\n");
//     return 0;
//   }
//   if (!*req)
//     *req = OCSP_REQUEST_new();
//   if (!*req)
//     goto err;

//   id = OCSP_cert_to_id(cert_id_md, cert, issuer);

//   if (!id || !sk_OCSP_CERTID_push(ids, id))
//     goto err;
//   if (!OCSP_request_add0_id(*req, id))
//     goto err;
//   return 1;

// err:
//   printf("%s", "Error Creating OCSP request");
//   // BIO_printf(bio_err, "Error Creating OCSP request\n");
//   return 0;
// }

// OCSP_RESPONSE *queryResponder(BIO *err, BIO *cbio, char *path, char *host,
//                               OCSP_REQUEST *req, int req_timeout) {
//   int fd;
//   int rv;
//   int i;
//   OCSP_REQ_CTX *ctx = NULL;
//   OCSP_RESPONSE *rsp = NULL;
//   fd_set confds;
//   struct timeval tv;

//   if (req_timeout != -1)
//     BIO_set_nbio(cbio, 1);

//   rv = BIO_do_connect(cbio);

//   if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
//     printf("%s", "Error connecting BIO");
//     return NULL;
//   }

//   if (BIO_get_fd(cbio, &fd) <= 0) {
//     printf("%s", "Can't get connection fd");
//     goto err;
//   }

//   if (req_timeout != -1 && rv <= 0) {
//     FD_ZERO(&confds);
//     FD_SET(fd, &confds);
//     tv.tv_usec = 0;
//     tv.tv_sec = req_timeout;
//     rv = select(fd + 1, NULL, &confds, NULL, &tv);
//     if (rv == 0) {
//       printf("%s", "Timeout on connect");
//       // BIO_puts(err, "Timeout on connect\n");
//       return NULL;
//     }
//   }

//   ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
//   if (!ctx)
//     return NULL;

//   if (!OCSP_REQ_CTX_add1_header(ctx, "Host", host))
//     goto err;

//   if (!OCSP_REQ_CTX_set1_req(ctx, req))
//     goto err;

//   for (;;) {
//     rv = OCSP_sendreq_nbio(&rsp, ctx);
//     if (rv != -1)
//       break;
//     if (req_timeout == -1)
//       continue;
//     FD_ZERO(&confds);
//     FD_SET(fd, &confds);
//     tv.tv_usec = 0;
//     tv.tv_sec = req_timeout;
//     if (BIO_should_read(cbio))
//       rv = select(fd + 1, &confds, NULL, NULL, &tv);
//     else if (BIO_should_write(cbio))
//       rv = select(fd + 1, NULL, &confds, NULL, &tv);
//     else {
//       printf("%s", "Unexpected retry condition");
//       goto err;
//     }

//     if (rv == 0) {
//       printf("%s", "Timeout on request");
//       break;
//     }
//     if (rv == -1) {
//       printf("%s", "Select error");
//       break;
//     }
//   }
// err:
//   if (ctx)
//     OCSP_REQ_CTX_free(ctx);

//   return rsp;
// }

// OCSP_RESPONSE *sendRequest(BIO *err, OCSP_REQUEST *req, char *host, char *path,
//                            char *port, int use_ssl, int req_timeout) {
//   BIO *cbio = NULL;
//   OCSP_RESPONSE *resp = NULL;
//   cbio = BIO_new_connect(host);
//   if (cbio && port && use_ssl == 0) {
//     BIO_set_conn_port(cbio, port);
//     resp = queryResponder(err, cbio, path, host, req, req_timeout);
//     if (!resp)
//       printf("%s", "Error querying OCSP responder");
//   }
//   if (cbio)
//     BIO_free_all(cbio);
//   return resp;
// }

// cert_status parseResponse(OCSP_RESPONSE *resp) {
//   int status, reason;
//   ASN1_INTEGER *serialNumber;
//   ASN1_TIME *revtime, *thisupd, *nextupd;
//   OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
//   OCSP_SINGLERESP *single = OCSP_resp_get0(bs, 0);
//   OCSP_CERTID *certId = (OCSP_CERTID *)OCSP_SINGLERESP_get0_id(single);

//   serialNumber = NULL;
//   revtime = thisupd = nextupd = NULL;

//   char *serialNumberHex = NULL;
//   if (OCSP_id_get0_info(NULL, NULL, NULL, &serialNumber, certId) == 1) {
//     BIGNUM *bnser = ASN1_INTEGER_to_BN(serialNumber, NULL);
//     char *serial_str = BN_bn2hex(bnser);
//     BN_free(bnser);
//     serialNumberHex = serial_str;
//   }
//   status =
//       OCSP_single_get0_status(single, &reason, &revtime, &thisupd, &nextupd);

//   OCSP_CERTID_free(certId);
//   // OCSP_SINGLERESP_free(single);
//   // OCSP_BASICRESP_free(bs);

//   return cert_status{status,
//                      reason,
//                      revtime ? ASN1_TIME2tring(revtime) : NULL,
//                      thisupd ? ASN1_TIME2tring(thisupd) : NULL,
//                      nextupd ? ASN1_TIME2tring(nextupd) : NULL,
//                      serialNumber ? serialNumberHex : NULL};
// }

// MARK: - OCSP

// /// 请求服务器进行证书检查
// ///
// ///     status code
// ///
// /// @return status code
// cert_status doCheckOCSP(X509 *cert, X509 *issuer) {
//   cert_status status;
//   BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
//   BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

//   if (issuer) {
//     // build ocsp request
//     OCSP_REQUEST *req = NULL;
//     STACK_OF(OCSP_CERTID) *ids = sk_OCSP_CERTID_new_null();
//     const EVP_MD *cert_id_md = EVP_sha1();
//     prepareRequest(&req, cert, cert_id_md, issuer, ids);

//     // loop through OCSP urls
//     STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(cert);
//     for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list); j++) {
//       int use_ssl, req_timeout = 30;
//       char *host = NULL, *port = NULL, *path = NULL;
//       char *ocsp_url = sk_OPENSSL_STRING_value(ocsp_list, j);
//       std::string ocsp_url0 =
//           std::string(sk_OPENSSL_STRING_value(ocsp_list, j));

//       if (OCSP_parse_url(ocsp_url, &host, &port, &path, &use_ssl) && !use_ssl) {
//         // send ocsp request
//         OCSP_RESPONSE *resp =
//             sendRequest(bio_err, req, host, path, port, use_ssl, req_timeout);
//         if (resp) {
//           OCSP_BASICRESP *bs = OCSP_response_get1_basic(resp);
//           int count = OCSP_resp_count(bs);

//           // see crypto/ocsp/ocsp_prn.c for examples parsing OCSP responses
//           int responder_status = OCSP_response_status(resp);

//           // parse response
//           if (responder_status == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
//             status = parseResponse(resp);
//           } else {
//             status = cert_status{V_OCSP_CERTSTATUS_UNKNOWN,
//                                  V_OCSP_CERTSTATUS_UNKNOWN + responder_status,
//                                  NULL,
//                                  NULL,
//                                  NULL,
//                                  NULL};
//           }
//           OCSP_RESPONSE_free(resp);
//         }
//       }
//       OPENSSL_free(host);
//       OPENSSL_free(path);
//       OPENSSL_free(port);
//     }
//     X509_email_free(ocsp_list);
//     OCSP_REQUEST_free(req);
//   }

//   BIO_free(bio_out);
//   BIO_free(bio_err);
//   return status;
// }

// cert_status doCheckStatusByOCSP(X509 *cert, const char issuer_bytes[]) {
//   BIO *bio_mem2 = BIO_new(BIO_s_mem());
//   BIO_puts(bio_mem2, issuer_bytes);
//   X509 *issuer = PEM_read_bio_X509(bio_mem2, NULL, NULL, NULL);
//   cert_status status = doCheckOCSP(cert, issuer);
//   BIO_free(bio_mem2);
//   X509_free(issuer);
//   return status;
// }

// MARK: - Cert Handler

// -1 无法解析证书
// 0 旧版本的证书
// 1 新版本证书
DLL_PUBLIC int check_cert_isG3CN(X509 *cert) { return is_G3_CN(cert) ? 1 : 0; }

DLL_PUBLIC int check_cert_bytes_isG3CN(const unsigned char *x509Bytes, int len) {
  int status = -1;
  X509 *cert = d2i_X509(NULL, &x509Bytes, len);
  if (!cert) {
    return -1;
  }

  // start check from apple ocsp
  status = check_cert_isG3CN(cert) ? 1 : 0;
  X509_free(cert);
  return status;
}

DLL_PUBLIC int check_p12_file_isG3CN(const char *fn, const char *password) {
  X509 *cert;
  EVP_PKEY *pkey;
  int status = -1;
  FILE *fp = fopen(fn, "rb");
  PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
  if (!p12) {
    fclose(fp);
    return -1;
  }

  PKCS12_parse(p12, password, &pkey, &cert, NULL);
  if (!cert) {
    PKCS12_free(p12);
    fclose(fp);
    return -1;
  }

  // start check from apple ocsp
  status = is_G3_CN(cert) ? 1 : 0;
  PKCS12_free(p12);
  fclose(fp);
  return status;
}

DLL_PUBLIC int check_p12_bytes_isG3CN(const unsigned char *in_bytes, int len,
                           const char *password) {
  X509 *cert;
  EVP_PKEY *pkey;
  int status = -1;
  PKCS12 *p12 = d2i_PKCS12(NULL, &in_bytes, len);
  if (!p12) {
    return -1;
  }

  PKCS12_parse(p12, password, &pkey, &cert, NULL);
  if (!cert) {
    PKCS12_free(p12);
    return -1;
  }

  // start check from apple ocsp
  status = is_G3_CN(cert) ? 1 : 0;
  PKCS12_free(p12);
  return status;
}

// cert_status check_cert_bytes_status(const unsigned char *in_bytes, int len,
//                                     const char ca_bytes[]) {
//   X509 *cert = d2i_X509(NULL, &in_bytes, len);
//   if (cert == NULL) {
//     return cert_status{V_OCSP_CERTSTATUS_UNKNOWN,
//                        V_OCSP_CERTSTATUS_UNKNOWN + 20,
//                        NULL,
//                        NULL,
//                        NULL,
//                        NULL};
//   }
//   cert_status status = doCheckStatusByOCSP(cert, ca_bytes);
//   X509_free(cert);
//   return status;
// }

// // -1 请求 Apple 服务器失败
// // -2 证书无法解析
// cert_status check_p12_file_status(const char *fn, const char *password,
//                                   const char ca_bytes[]) {
//   X509 *cert;
//   EVP_PKEY *pkey;
//   FILE *fp = fopen(fn, "rb");
//   PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
//   if (!p12) {
//     fclose(fp);
//     return cert_status{V_OCSP_CERTSTATUS_UNKNOWN,
//                        V_OCSP_CERTSTATUS_UNKNOWN + 20,
//                        NULL,
//                        NULL,
//                        NULL,
//                        NULL};
//   }

//   PKCS12_parse(p12, password, &pkey, &cert, NULL);
//   if (!cert) {
//     PKCS12_free(p12);
//     fclose(fp);
//     return cert_status{V_OCSP_CERTSTATUS_UNKNOWN,
//                        V_OCSP_CERTSTATUS_UNKNOWN + 20,
//                        NULL,
//                        NULL,
//                        NULL,
//                        NULL};
//   }

//   // start check from apple ocsp
//   return doCheckStatusByOCSP(cert, ca_bytes);
// }

// cert_status check_p12_bytes_status(const unsigned char *in_bytes, int len,
//                                    const char *password,
//                                    const char ca_bytes[]) {
//   X509 *cert;
//   EVP_PKEY *pkey;
//   PKCS12 *p12 = d2i_PKCS12(NULL, &in_bytes, len);
//   if (!p12) {
//     return cert_status{V_OCSP_CERTSTATUS_UNKNOWN,
//                        V_OCSP_CERTSTATUS_UNKNOWN + 20,
//                        NULL,
//                        NULL,
//                        NULL,
//                        NULL};
//   }

//   PKCS12_parse(p12, password, &pkey, &cert, NULL);
//   if (!cert) {
//     PKCS12_free(p12);
//     return cert_status{V_OCSP_CERTSTATUS_UNKNOWN,
//                        V_OCSP_CERTSTATUS_UNKNOWN + 20,
//                        NULL,
//                        NULL,
//                        NULL,
//                        NULL};
//   }

//   // start check from apple ocsp
//   return doCheckStatusByOCSP(cert, ca_bytes);
// }