// Helper program based on the tor source code; makes a certificate
// to use in testing our TLS implementation.
//
// This has to be done using OpenSSL's C API since there's no way to emulate
// Tor's particular flavor of weirdness (version 3 certs with no extensions)
// from the OpenSSL CLI.
//
// This is not meant to be used for anything but testing Arti.  If you use
// it for something else, you might regret it deeply.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

 X509_NAME *
tor_x509_name_new(const char *cname)
{
  int nid;
  X509_NAME *name;
  if (!(name = X509_NAME_new()))
    return NULL;
  if ((nid = OBJ_txt2nid("commonName")) == NID_undef) goto error;
  if (!(X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC,
                                   (unsigned char*)cname, -1, -1, 0)))
    goto error;
  return name;

 error:
  X509_NAME_free(name);
  return NULL;
}

X509 *
tor_tls_create_certificate(EVP_PKEY *pkey,
                            EVP_PKEY *sign_pkey,
                            const char *cname,
                            const char *cname_sign,
                            unsigned int cert_lifetime)
{
  /* OpenSSL generates self-signed certificates with random 64-bit serial
   * numbers, so let's do that too. */
#define SERIAL_NUMBER_SIZE 8

  BIGNUM *serial_number = NULL;
  unsigned char serial_tmp[SERIAL_NUMBER_SIZE];
  X509 *x509 = NULL;
  X509_NAME *name = NULL, *name_issuer=NULL;

  time_t start_time = time(NULL);
  time_t end_time = start_time + cert_lifetime;

  if (!(x509 = X509_new()))
    goto error;
  if (!(X509_set_version(x509, 2)))
    goto error;

  { /* our serial number is 8 random bytes. */
    RAND_bytes(serial_tmp, sizeof(serial_tmp));
    if (!(serial_number = BN_bin2bn(serial_tmp, sizeof(serial_tmp), NULL)))
      goto error;
    if (!(BN_to_ASN1_INTEGER(serial_number, X509_get_serialNumber(x509))))
      goto error;
  }

  if (!(name = tor_x509_name_new(cname)))
    goto error;
  if (!(X509_set_subject_name(x509, name)))
    goto error;
  if (!(name_issuer = tor_x509_name_new(cname_sign)))
    goto error;
  if (!(X509_set_issuer_name(x509, name_issuer)))
    goto error;

  if (!X509_time_adj(X509_get_notBefore(x509),0,&start_time))
    goto error;
  if (!X509_time_adj(X509_get_notAfter(x509),0,&end_time))
    goto error;
  if (!X509_set_pubkey(x509, pkey))
    goto error;

  if (!X509_sign(x509, sign_pkey, EVP_sha256()))
    goto error;

  goto done;
 error:
  fprintf(stderr, "Error making certificate\n");
  if (x509) {
    X509_free(x509);
    x509 = NULL;
  }
 done:
  if (serial_number)
    BN_clear_free(serial_number);
  if (name)
    X509_NAME_free(name);
  if (name_issuer)
    X509_NAME_free(name_issuer);
  return x509;

#undef SERIAL_NUMBER_SIZE
}



int
main(int argc, char **argv)
{
  OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

  EVP_PKEY *link = NULL, *sign = NULL;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  assert(ctx);

  if (EVP_PKEY_keygen_init(ctx) <= 0) {
    puts("BLAH");
    return 1;
  }
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

  int r1 = EVP_PKEY_keygen(ctx, &link);
  int r2 = EVP_PKEY_keygen(ctx, &sign);
  assert(r1 == 1 && r2 == 1);

  X509* x509 = tor_tls_create_certificate(link,
                                          sign,
                                          "Hello",
                                          "World",
                                          86400);
  if (!x509) {
    return 1;
  }

  FILE *key = fopen("test.key", "w");
  int r3 = PEM_write_PrivateKey(key, link, NULL, NULL, 0 , NULL, NULL);
  assert(r3 == 1);
  fclose(key);

  FILE *cert = fopen("test.crt", "w");
  int r4 = PEM_write_X509(cert, x509);
  assert(r4 == 1);
  fclose(cert);

  puts("OK.");
  
  return 0;
}
