//
//  libmagicsignature.cpp
//  libmagicsignature
//
//  Created by MartinLau on 26/5/2020.
//  Copyright © 2020 tutuapp. All rights reserved.
//

#include "libmagicsignature.h"

#include "ldid.hpp"

#include <dirent.h>
#include <getopt.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>

#include <dirent.h>
#include <inttypes.h>
#include <string.h>

#include <sys/stat.h>

#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

// MARK: - private method

const char *AppleRootCertificateData =
    ""
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET\n"
    "MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv\n"
    "biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0\n"
    "MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw\n"
    "bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx\n"
    "FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\n"
    "ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+\n"
    "+FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1\n"
    "XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w\n"
    "tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW\n"
    "q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM\n"
    "aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E\n"
    "BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3\n"
    "R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE\n"
    "ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93\n"
    "d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl\n"
    "IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0\n"
    "YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj\n"
    "b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp\n"
    "Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc\n"
    "NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP\n"
    "y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7\n"
    "R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg\n"
    "xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP\n"
    "IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX\n"
    "UKqK1drk/NAJBzewdXUh\n"
    "-----END CERTIFICATE-----\n";

const char *AppleWWDRCertificateData =
    ""
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEUTCCAzmgAwIBAgIQfK9pCiW3Of57m0R6wXjF7jANBgkqhkiG9w0BAQsFADBi\n"
    "MQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBw\n"
    "bGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3Qg\n"
    "Q0EwHhcNMjAwMjE5MTgxMzQ3WhcNMzAwMjIwMDAwMDAwWjB1MUQwQgYDVQQDDDtB\n"
    "cHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZpY2F0aW9u\n"
    "IEF1dGhvcml0eTELMAkGA1UECwwCRzMxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJ\n"
    "BgNVBAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2PWJ/KhZ\n"
    "C4fHTJEuLVaQ03gdpDDppUjvC0O/LYT7JF1FG+XrWTYSXFRknmxiLbTGl8rMPPbW\n"
    "BpH85QKmHGq0edVny6zpPwcR4YS8Rx1mjjmi6LRJ7TrS4RBgeo6TjMrA2gzAg9Dj\n"
    "+ZHWp4zIwXPirkbRYp2SqJBgN31ols2N4Pyb+ni743uvLRfdW/6AWSN1F7gSwe0b\n"
    "5TTO/iK1nkmw5VW/j4SiPKi6xYaVFuQAyZ8D0MyzOhZ71gVcnetHrg21LYwOaU1A\n"
    "0EtMOwSejSGxrC5DVDDOwYqGlJhL32oNP/77HK6XF8J4CjDgXx9UO0m3JQAaN4LS\n"
    "VpelUkl8YDib7wIDAQABo4HvMIHsMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0j\n"
    "BBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wRAYIKwYBBQUHAQEEODA2MDQGCCsG\n"
    "AQUFBzABhihodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNh\n"
    "MC4GA1UdHwQnMCUwI6AhoB+GHWh0dHA6Ly9jcmwuYXBwbGUuY29tL3Jvb3QuY3Js\n"
    "MB0GA1UdDgQWBBQJ/sAVkPmvZAqSErkmKGMMl+ynsjAOBgNVHQ8BAf8EBAMCAQYw\n"
    "EAYKKoZIhvdjZAYCAQQCBQAwDQYJKoZIhvcNAQELBQADggEBAK1lE+j24IF3RAJH\n"
    "Qr5fpTkg6mKp/cWQyXMT1Z6b0KoPjY3L7QHPbChAW8dVJEH4/M/BtSPp3Ozxb8qA\n"
    "HXfCxGFJJWevD8o5Ja3T43rMMygNDi6hV0Bz+uZcrgZRKe3jhQxPYdwyFot30ETK\n"
    "XXIDMUacrptAGvr04NM++i+MZp+XxFRZ79JI9AeZSWBZGcfdlNHAwWx/eCHvDOs7\n"
    "bJmCS1JgOLU5gm3sUjFTvg+RTElJdI+mUcuER04ddSduvfnSXPN/wmwLCTbiZOTC\n"
    "NwMUGdXqapSqqdv+9poIZ4vvK7iqF0mDr8/LvOnP6pVxsLRFoszlh6oKw0E6eVza\n"
    "UDSdlTs=\n"
    "-----END CERTIFICATE-----\n";

const char *LegacyAppleWWDRCertificateData =
    ""
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEIjCCAwqgAwIBAgIIAd68xDltoBAwDQYJKoZIhvcNAQEFBQAwYjELMAkGA1UE\n"
    "BhMCVVMxEzARBgNVBAoTCkFwcGxlIEluYy4xJjAkBgNVBAsTHUFwcGxlIENlcnRp\n"
    "ZmljYXRpb24gQXV0aG9yaXR5MRYwFAYDVQQDEw1BcHBsZSBSb290IENBMB4XDTEz\n"
    "MDIwNzIxNDg0N1oXDTIzMDIwNzIxNDg0N1owgZYxCzAJBgNVBAYTAlVTMRMwEQYD\n"
    "VQQKDApBcHBsZSBJbmMuMSwwKgYDVQQLDCNBcHBsZSBXb3JsZHdpZGUgRGV2ZWxv\n"
    "cGVyIFJlbGF0aW9uczFEMEIGA1UEAww7QXBwbGUgV29ybGR3aWRlIERldmVsb3Bl\n"
    "ciBSZWxhdGlvbnMgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwggEiMA0GCSqGSIb3\n"
    "DQEBAQUAA4IBDwAwggEKAoIBAQDKOFSmy1aqyCQ5SOmM7uxfuH8mkbw0U3rOfGOA\n"
    "YXdkXqUHI7Y5/lAtFVZYcC1+xG7BSoU+L/DehBqhV8mvexj/avoVEkkVCBmsqtsq\n"
    "Mu2WY2hSFT2Miuy/axiV4AOsAX2XBWfODoWVN2rtCbauZ81RZJ/GXNG8V25nNYB2\n"
    "NqSHgW44j9grFU57Jdhav06DwY3Sk9UacbVgnJ0zTlX5ElgMhrgWDcHld0WNUEi6\n"
    "Ky3klIXh6MSdxmilsKP8Z35wugJZS3dCkTm59c3hTO/AO0iMpuUhXf1qarunFjVg\n"
    "0uat80YpyejDi+l5wGphZxWy8P3laLxiX27Pmd3vG2P+kmWrAgMBAAGjgaYwgaMw\n"
    "HQYDVR0OBBYEFIgnFwmpthhgi+zruvZHWcVSVKO3MA8GA1UdEwEB/wQFMAMBAf8w\n"
    "HwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wLgYDVR0fBCcwJTAjoCGg\n"
    "H4YdaHR0cDovL2NybC5hcHBsZS5jb20vcm9vdC5jcmwwDgYDVR0PAQH/BAQDAgGG\n"
    "MBAGCiqGSIb3Y2QGAgEEAgUAMA0GCSqGSIb3DQEBBQUAA4IBAQBPz+9Zviz1smwv\n"
    "j+4ThzLoBTWobot9yWkMudkXvHcs1Gfi/ZptOllc34MBvbKuKmFysa/Nw0Uwj6OD\n"
    "Dc4dR7Txk4qjdJukw5hyhzs+r0ULklS5MruQGFNrCk4QttkdUGwhgAqJTleMa1s8\n"
    "Pab93vcNIx0LSiaHP7qRkkykGRIZbVf1eliHe2iK5IaMSuviSRSqpd1VAKmuu0sw\n"
    "ruGgsbwpgOYJd+W+NKIByn/c4grmO7i77LpilfMFY0GCzQ87HUyVpNur+cmV6U/k\n"
    "TecmmYHpvPm0KdIBembhLoz2IYrF+Hjhga6/05Cdqa3zr/04GpZnMBxRpVzscYqC\n"
    "tGwPDBUf\n"
    "-----END CERTIFICATE-----\n";

std::string createCert(const char *pkcs12_file, const char *password) {
  BIO *p12Bio = BIO_new_file(pkcs12_file, "r");
  auto inputP12 = d2i_PKCS12_bio(p12Bio, NULL);

  // Extract key + certificate from .p12.
  EVP_PKEY *key;
  X509 *certificate;
  PKCS12_parse(inputP12, password, &key, &certificate, NULL);

  // Prepare certificate chain of trust.
  auto *certificates = sk_X509_new(NULL);

  BIO *rootCertificateBuffer = BIO_new_mem_buf(
      AppleRootCertificateData, (int)strlen(AppleRootCertificateData));
  BIO *wwdrCertificateBuffer = NULL;
  unsigned long issuerHash = X509_issuer_name_hash(certificate);
  if (issuerHash == 0x817d2f7a) {
    // Use legacy WWDR certificate.
    wwdrCertificateBuffer =
        BIO_new_mem_buf(LegacyAppleWWDRCertificateData,
                        (int)strlen(LegacyAppleWWDRCertificateData));
  } else {
    // Use latest WWDR certificate.
    wwdrCertificateBuffer = BIO_new_mem_buf(
        AppleWWDRCertificateData, (int)strlen(AppleWWDRCertificateData));
  }

  // Extract certificates from .pem.
  auto rootCertificate =
      PEM_read_bio_X509(rootCertificateBuffer, NULL, NULL, NULL);
  if (rootCertificate != NULL) {
    sk_X509_push(certificates, rootCertificate);
  }
  auto wwdrCertificate =
      PEM_read_bio_X509(wwdrCertificateBuffer, NULL, NULL, NULL);
  if (wwdrCertificate != NULL) {
    sk_X509_push(certificates, wwdrCertificate);
  }

  // Create new .p12 in memory with private key and certificate chain.
  char emptyString[] = "";
  auto outputP12 = PKCS12_create(emptyString, emptyString, key, certificate,
                                 certificates, 0, 0, 0, 0, 0);
  BIO *outputP12Buffer = BIO_new(BIO_s_mem());
  i2d_PKCS12_bio(outputP12Buffer, outputP12);

  char *buffer = NULL;
  int size = BIO_get_mem_data(outputP12Buffer, &buffer);

  PKCS12_free(inputP12);
  PKCS12_free(outputP12);
  BIO_free(rootCertificateBuffer);
  BIO_free(wwdrCertificateBuffer);
  BIO_free(p12Bio);

  std::string output(buffer, size);
  return output;
}

/// 撷取档案大小
/// @param fd 档案控制代码
int64_t get_file_size(int fd) {
  int64_t nSize = 0;
  struct stat stbuf;
  if (0 == fstat(fd, &stbuf)) {
    if (S_ISREG(stbuf.st_mode)) {
      nSize = stbuf.st_size;
    }
  }
  return (nSize < 0 ? 0 : nSize);
}

/// 撷取指定资料夹下所有档案(资料夹)数量
/// @param rootpath 指定资料夹
int get_subpath_count(const char *rootpath) {
  int total = 0;
  DIR *dir = opendir(rootpath);
  if (NULL == dir) {
    return -1;
  }

  while (1) {
    struct dirent *dire = NULL;
    dire = readdir(dir);
    if (NULL == dire) {
      break;
    }
    if ((strcmp(dire->d_name, ".") == 0) || (strcmp(dire->d_name, "..") == 0)) {
      continue;
    }
    if (dire->d_type == DT_REG) {
      ++total;
      continue;
    }
    if (dire->d_type == DT_DIR) {
      char buf[1024];
      bzero(buf, sizeof(buf));
      sprintf(buf, "%s/%s", rootpath, dire->d_name);
      ++total;
      total += get_subpath_count(buf);
    }
  }
  closedir(dir);
  return total;
}

// MARK: - cert handler

void init_openssl() {
  OpenSSL_add_all_algorithms();
#if OPENSSL_VERSION_MAJOR >= 3
  OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
  OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
#endif
}

// MARK: - mobild provision handler

bool read_x509_name_entry_value(X509_NAME *name, int nid, char **val) {
  int index = X509_NAME_get_index_by_NID(name, nid, -1);
  X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, index);
  if (entry) {
    ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
    std::string name_str(
        reinterpret_cast<const char *>(ASN1_STRING_get0_data(data)));
    *val = strdup(name_str.c_str());
    name_str.clear();
    return true;
  }
  return false;
}

long parseMobileprovision(const char *provisionFile, char **provContent) {
  std::string provisionData("");
  provisionData.clear();
  FILE *fp = fopen(provisionFile, "rb");
  if (NULL != fp) {
    provisionData.reserve(get_file_size(fileno(fp)));

    char buf[4096] = {0};
    size_t nread = fread(buf, 1, 4096, fp);
    while (nread > 0) {
      provisionData.append(buf, nread);
      nread = fread(buf, 1, 4096, fp);
    }
    fclose(fp);
    if (provisionData.empty()) {
      return -1;
    }
    const char *p_Str = provisionData.c_str();
    size_t len = provisionData.length();
    char *start = (char *)memmem(
        p_Str, len, "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0", 47);
    if (start) {
      char *end = (char *)memmem(start, (uintptr_t)start - len, "</plist>", 8);
      if (end) {
        *provContent = start;
        return 8 + end - start;
      }
    }
  }
  return -1;
}

bool decodeProvisionFile(const char *provisionFile, char **provContent,
                         int *len) {
  std::string provisionData("");
  provisionData.clear();
  FILE *fp = fopen(provisionFile, "rb");
  if (NULL != fp) {
    provisionData.reserve(get_file_size(fileno(fp)));

    char buf[4096] = {0};
    size_t nread = fread(buf, 1, 4096, fp);
    while (nread > 0) {
      provisionData.append(buf, nread);
      nread = fread(buf, 1, 4096, fp);
    }
    fclose(fp);
    if (provisionData.empty()) {
      return false;
    }
    BIO *in = BIO_new(BIO_s_mem());
    OPENSSL_assert(
        (size_t)BIO_write(in, provisionData.data(), provisionData.size()) ==
        provisionData.size());
    CMS_ContentInfo *cms = d2i_CMS_bio(in, NULL);
    if (!cms) {
      return false;
    }
    ASN1_OCTET_STRING **pos = CMS_get0_content(cms);
    if (!pos) {
      return false;
    }
    if (!(*pos)) {
      return false;
    }
    std::string strContentOutput("");
    strContentOutput.clear();
    strContentOutput.append((const char *)(*pos)->data, (*pos)->length);
    const char *content = strContentOutput.c_str();
    *len = strContentOutput.length();
    *provContent = strdup(content);
    return true;
  }
  return false;
}

bool get_x509_info(X509 *cert, certificate_info *s_cert) {
  char *commonName;
  int nid = OBJ_txt2nid("CN"); // common_name
  X509_NAME *issuer = X509_get_issuer_name(cert);
  if (issuer) {
    if (read_x509_name_entry_value(issuer, nid, &commonName)) {
      (*s_cert).IssuerCN = commonName;
    }
    X509_NAME_free(issuer);
  }

  X509_NAME *subject = X509_get_subject_name(cert);
  if (!subject) {
    return false;
  }
  if (read_x509_name_entry_value(subject, nid, &commonName)) {
    (*s_cert).SubjectCN = commonName;
  }
  X509_NAME_free(subject);

  const ASN1_INTEGER *serialNumber = X509_get0_serialNumber(cert);
  BIGNUM *bnser = ASN1_INTEGER_to_BN(serialNumber, NULL);
  char *serial_str = BN_bn2hex(bnser);
  BN_free(bnser);
  (*s_cert).SerialNumber = serial_str;
  return true;
}

bool get_x509_bytes_info(const unsigned char *in_bytes, int len,
                         certificate_info *s_cert) {
  certificate_info x_cert;
  X509 *cert = d2i_X509(NULL, &in_bytes, len);
  if (cert == NULL) {
    return false;
  }
  return get_x509_info(cert, s_cert);
}

bool get_pkcs12_file_info(const char *pkcs12, const char *password,
                          certificate_info *s_cert) {
  X509 *cert;
  EVP_PKEY *pkey;
  FILE *fp = fopen(pkcs12, "rb");
  PKCS12 *p12 = d2i_PKCS12_fp(fp, NULL);
  if (!p12) {
    fclose(fp);
    return false;
  }

  PKCS12_parse(p12, password, &pkey, &cert, NULL);
  if (cert) {
    bool res = get_x509_info(cert, s_cert);
    PKCS12_free(p12);
    return res;
  }
  fclose(fp);
  return false;
}

bool get_pkcs12_info(const unsigned char *in_bytes, int len,
                     const char *password, certificate_info *s_cert) {
  X509 *cert;
  EVP_PKEY *pkey;
  PKCS12 *p12 = d2i_PKCS12(NULL, &in_bytes, len);
  if (!p12) {
    return false;
  }

  PKCS12_parse(p12, password, NULL, &cert, NULL);
  if (cert) {
    bool res = get_x509_info(cert, s_cert);
    PKCS12_free(p12);
    return res;
  }
  return false;
}

// MARK: - codesign handler

void ldid_sign_bundle(const char *bundle, const char *pkcs12,
                      const char *password, const char *entitlements,
                      void (*codesignProgress)(const void *, const char *,
                                               double progress),
                      const void *context) {
  const std::string path(bundle);
  ldid::DiskFolder appBundle(path);
  std::string key = createCert(pkcs12, password);

  std::string lastItem("");
  // platform:
  // enum PlatformIdentifier : UInt32 {
  //   kPlatformMacOS = 1,       // Mac OS X
  //   kPlatformiOS = 2,         // iOS
  //   kPlatformwatchOS = 3,     // watchOS
  //   kPlatformtvOS = 4,        // tvOS
  //   kPlatformMacCatalyst = 6, // Mac Catalyst
  //   kPlatformMacOSAll = 14,   // Mac OS X (All architectures)
  //   kPlatformiOSAll = 15,     // iOS (All architectures)
  //   kPlatformwatchOSAll = 16, // watchOS (All architectures)
  //   kPlatformtvOSAll = 17     // tvOS (All architectures)
  // };

  ldid::Sign(
      "", appBundle, key, "",
      ldid::fun([&](const std::string &, const std::string &) -> std::string {
        return entitlements;
      }),
      false, 0, ldid::fun([&](const std::string &item) {
        lastItem = item;
        if (codesignProgress != NULL) {
          codesignProgress(context, lastItem.c_str(), 0);
        }
      }),
      ldid::fun([&](const double signingProgress) {
        if (codesignProgress != NULL) {
          if (lastItem != "") {
            codesignProgress(context, lastItem.c_str(), signingProgress);
            if (signingProgress == 1) {
              lastItem = "";
            }
          }
        }
      }));
}
