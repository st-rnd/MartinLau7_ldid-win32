//
//  libmagicsignature.h
//  libmagicsignature
//
//  Created by MartinLau on 6/3/2020.
//  Copyright © 2020 tutuapp. All rights reserved.
//

#ifndef libmagicsignature_h
#define libmagicsignature_h

#if defined(__WIN32__) || defined(_MSC_VER) || defined(__MINGW32__)
  #ifdef BUILDING_DLL
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__((dllexport))
    #else
      #define DLL_PUBLIC __declspec(dllexport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #else
    #ifdef __GNUC__
      #define DLL_PUBLIC __attribute__((dllimport))
    #else
      #define DLL_PUBLIC __declspec(dllimport) // Note: actually gcc seems to also supports this syntax.
    #endif
  #endif
#else
  #if __GNUC__ >= 4
    #define DLL_PUBLIC __attribute__ ((visibility("default")))
    #define DLL_LOCAL  __attribute__ ((visibility("hidden")))
  #else
    #define DLL_PUBLIC
    #define DLL_LOCAL
  #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <openssl/x509.h>

struct x509_info {
    char *IssuerCN;
    char *SubjectCN;
    char *SerialNumber;
};

// typedef struct c_string {
// 	char	*c_data;
// 	int		len;
// } CSString;

// struct x509_status {
//     int status;
//     int reason;
//     char *revtime;
//     char *thisUpdate;
//     char *nextUpdate;
//     char *serialNumber;
// };

typedef struct x509_info certificate_info;
// typedef struct x509_status cert_status;

// MARK: - cert handler

DLL_PUBLIC void init_openssl();

DLL_PUBLIC bool get_x509_info(X509 *cert, certificate_info *s_cert);

DLL_PUBLIC bool get_x509_bytes_info(const unsigned char *in_bytes, int len, certificate_info *s_cert);

DLL_PUBLIC bool get_pkcs12_file_info(const char *pkcs12, const char *password, certificate_info *s_cert);

DLL_PUBLIC bool get_pkcs12_info(const unsigned char *in_bytes, int len, const char *password, certificate_info *s_cert);

/// 检查证书(*.cert) 是否为 G3 证书
/// @return status ( -1: 无法解析 / 0: not G3 CN Cert / 1: G3 CN Cert)
DLL_PUBLIC int check_cert_isG3CN(X509 *cert);

/// 检查证书(*.cert) 是否为 G3 证书
/// @return status ( -1: 无法解析 / 0: not G3 CN Cert / 1: G3 CN Cert)
DLL_PUBLIC int check_cert_bytes_isG3CN(const unsigned char *x509Bytes, int len);

/// 检查证书(*.p12) 是否为 G3 证书
/// @return status ( -1: 无法解析 / 0: not G3 CN Cert / 1: G3 CN Cert)
DLL_PUBLIC int check_p12_file_isG3CN(const char *fn, const char *password);

/// 检查证书(*.p12) 是否为 G3 证书
/// @return status ( -1: 无法解析 / 0: not G3 CN Cert / 1: G3 CN Cert)
DLL_PUBLIC int check_p12_bytes_isG3CN(const unsigned char *in_bytes, int len, const char *password);

// /// 检查证书状态
// cert_status check_cert_bytes_status(const unsigned char *in_bytes, int len, const char issuer_bytes[]);

// /// 检查证书状态
// cert_status check_p12_file_status(const char *fn, const char *password, const char issuer_bytes[]);

// /// 检查证书状态
// cert_status check_p12_bytes_status(const unsigned char *in_bytes, int len, const char *password, const char issuer_bytes[]);

// MARK: - mobild provision handler

DLL_PUBLIC long parseMobileprovision(const char *provisionFile, char **provContent);

DLL_PUBLIC bool decodeProvisionFile(const char *provisionFile, char **provContent, int *len);

// MARK: - codesign handler

// liblbid codesignature
DLL_PUBLIC void ldid_sign_bundle(const char *bundle, const char *pkcs12, const char *password, const char *entitlements, void (*codesignProgress)(const void *, const char *, double progress), const void *context);

#ifdef __cplusplus
}
#endif
#endif /* libmagicsignature_h */
