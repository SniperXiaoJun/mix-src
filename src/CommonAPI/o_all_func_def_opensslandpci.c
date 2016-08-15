#include "o_all_func_def.h"

#include "openssl_func_def.h"	// OpenSSL功能定义
#include "pci_func_def.h"

#include "sm2.h"

#include "stdlib.h"
#include "string.h"
#include "openssl/x509v3.h"

#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/des.h>
#include <openssl/pkcs12.h>
#include <openssl/md5.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>

#include "FILE_LOG.h"

extern EC_GROUP *g_group;

unsigned int SM2SignAsn1Convert(
	unsigned char *pbR, unsigned int nRLen,
	unsigned char *pbS, unsigned int nSLen,
	unsigned char *pbOutDer, unsigned int *pOutDerLen);

unsigned int OPF_SM2SignCert(void * hSessionHandle,
	const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
	unsigned char * pbX509CertSigned, unsigned int * puiX509CertSignedLen)
{
	unsigned int rv = -1;

	X509 * x509 =  NULL;
	unsigned char sig_value[BUFFER_LEN_1K] = {0};
	unsigned int sig_len = BUFFER_LEN_1K;

	unsigned int uiPublicKeyXlen = SM2_BYTES_LEN;
	unsigned int uiPublicKeyYlen = SM2_BYTES_LEN;

	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;

	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	unsigned int cert_buffer_len = BUFFER_LEN_1K * 4;
	unsigned char cert_buffer_data[BUFFER_LEN_1K * 4] = {0};

	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;

	ptr_out = cert_buffer_data;
	ptr_in = pbX509Cert;

	x509 = d2i_X509(NULL, &ptr_in, uiX509CertLen);

	memcpy(pubkey_xy_value, "\x04", 1);

	cert_buffer_len =i2d_X509_CINF(x509->cert_info,&ptr_out);

	rv = PCI_ExportRootSM2Keys(hSessionHandle,pubkey_xy_value + 1,&uiPublicKeyXlen,pubkey_xy_value + 1 + SM2_BYTES_LEN,&uiPublicKeyYlen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"pubkey_xy_value");
	FILE_LOG_HEX(file_log_name, pubkey_xy_value, SM2_BYTES_LEN * 2 + 1);
	if (rv)
	{
		goto err;
	}

	rv = tcm_get_message_hash(cert_buffer_data, cert_buffer_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if (rv)
	{
		goto err;
	}

	rv = PCI_SignWithRootSM2Keys(hSessionHandle, NULL,0,digest_value,digest_len,0,sig_value,&sig_len);
	if (rv)
	{
		goto err;
	}

	rv = SM2SignAsn1Convert(sig_value,SM2_BYTES_LEN, sig_value + SM2_BYTES_LEN,SM2_BYTES_LEN, encode_value, &encode_len);
	if (rv)
	{
		goto err;
	}

	ASN1_BIT_STRING_set(x509->signature,encode_value, encode_len);
	x509->signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	x509->signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

	ptr_out = pbX509CertSigned;
	* puiX509CertSignedLen =  i2d_X509(x509, &ptr_out);

	rv = 0;
err:

	if (x509)
	{
		X509_free(x509);
	}

	return rv;
}



unsigned int OPF_SM2SignCRL(void * hSessionHandle,
	const unsigned char *pbX509Cert, unsigned int uiX509CertLen,
	const unsigned char *pbCRL, unsigned int uiCRL,unsigned int uiAlg,
	unsigned char * pbCRLSigned, unsigned int * puiCRLSigned)
{
	unsigned int rv = -1;
	X509_CRL * crl =  NULL;
	X509 * x509 =  NULL;
	unsigned char sig_value[BUFFER_LEN_1K] = {0};
	unsigned int sig_len = BUFFER_LEN_1K;

	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	unsigned int crl_buffer_len = BUFFER_LEN_1K * 4;
	unsigned char crl_buffer_value[BUFFER_LEN_1K * 4] = {0};
	unsigned char *pcrl = crl_buffer_value;

	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;

	ptr_out = pbCRLSigned;
	
	ptr_in = pbCRL;
	crl = d2i_X509_CRL(NULL, (const unsigned char **)&ptr_in,uiCRL);

	if (NULL == crl)
	{
		goto err;
	}

	ptr_in = pbX509Cert;
	x509 = d2i_X509(NULL, (const unsigned char **)&ptr_in,uiX509CertLen);

	if (NULL == x509)
	{
		goto err;
	}

	crl_buffer_len =i2d_X509_CRL_INFO(crl->crl,&pcrl);

	rv = tcm_get_message_hash(crl_buffer_value, crl_buffer_len,"1234567812345678", 16, 
		x509->cert_info->key->public_key->data,
		x509->cert_info->key->public_key->length,
		digest_value,&digest_len);

	FILE_LOG_STRING(file_log_name, "rv");
	FILE_LOG_NUMBER(file_log_name, rv);
	FILE_LOG_HEX(file_log_name, crl_buffer_value, crl_buffer_len);
	FILE_LOG_STRING(file_log_name, "digest_value");
	FILE_LOG_HEX(file_log_name, digest_value, digest_len);

	if (rv)
	{
		goto err;
	}

	rv = PCI_SignWithRootSM2Keys(hSessionHandle, NULL,0,digest_value,digest_len,0,sig_value,&sig_len);
	FILE_LOG_STRING(file_log_name, "rv");
	FILE_LOG_NUMBER(file_log_name, rv);
	FILE_LOG_STRING(file_log_name, "sig");
	FILE_LOG_HEX(file_log_name, sig_value, sig_len);
	if (rv)
	{
		goto err;
	}

	rv = SM2SignAsn1Convert(sig_value,SM2_BYTES_LEN, sig_value + SM2_BYTES_LEN,SM2_BYTES_LEN, encode_value, &encode_len);
	FILE_LOG_STRING(file_log_name, "rv");
	FILE_LOG_NUMBER(file_log_name, rv);
	FILE_LOG_STRING(file_log_name, "encode_value");
	FILE_LOG_HEX(file_log_name, encode_value, encode_len);
	if (rv)
	{
		goto err;
	}

	ASN1_BIT_STRING_set(crl->signature,encode_value, encode_len);
	crl->signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	crl->signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

	*puiCRLSigned = i2d_X509_CRL(crl, &ptr_out);

	rv = 0;
err:
	if(crl)
	{
		X509_CRL_free(crl);
	}

	if (x509)
	{
		X509_free(x509);
	}

	return rv;
}
