#include "openssl_func_def.h"
#include "o_all_type_def.h"
#include "FILE_LOG.h"
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>
#include "o_all_func_def.h"
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

#include "gm-ecc-512.h"
#include "gm-hash-bit.h"

#include "string.h"
#include "openssl/x509v3.h"



extern EC_GROUP *g_group512;


int copy_extensions(X509 *x, X509_REQ *req, int copy_type);
short Add_Ext(X509 *cert, X509 * root, int nid, char *value);

unsigned int OpenSSL_AddNameByID(X509_NAME * aX509Name,  unsigned int aType, unsigned char * aDataValue, unsigned int aDataLen, unsigned int aDataType);//��Ӣ�Ĵ���
unsigned int OpenSSL_AddNameByName(X509_NAME * aX509Name, const char * aType, unsigned char * aDataValue, unsigned int aDataLen, unsigned int aDataType);//��Ӣ�Ĵ���


EVP_PKEY * OpenSSL_NewEVP_PKEY_OF_GMECC512_PublicKey(
	const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen
	)
{
	EVP_PKEY	*pkey = NULL;
	EC_KEY		*ec = NULL;
	BN_CTX      *ctx=NULL;
	EC_POINT    *pubkey=NULL;
	BIGNUM      *pubkey_x=NULL, *pubkey_y=NULL;

	// 初始化证书公钥
	if((pkey = EVP_PKEY_new()) == NULL)
	{
		goto err;
	}
	if (!(ctx = BN_CTX_new()) )
	{
		goto err;
	}
	ec = EC_KEY_new();
	if (NULL==ec)
	{
		goto err;
	}
	if (!(EC_KEY_set_group(ec, g_group512)))
	{
		goto err;
	}
	if (!(pubkey = EC_POINT_new(g_group512)))
	{ 
		goto err;
	}
	if (!EC_KEY_generate_key(ec))
	{
		goto err;
	}

	/* set public key */
	pubkey_x = BN_bin2bn( pbPublicKeyX,uiPublicKeyXLen, NULL );
	if (NULL == pubkey_x)
	{
		goto err;
	} 

	pubkey_y = BN_bin2bn( pbPublicKeyY,uiPublicKeyYLen, NULL );
	if ( NULL == pubkey_y)
	{
		goto err;
	} 

	if ( !EC_POINT_set_affine_coordinates_GFp(g_group512, pubkey, pubkey_x, pubkey_y, ctx) )
	{
		goto err;
	} 

	if ( !EC_KEY_set_public_key(ec, pubkey) )
	{
		goto err;
	} 

	if(!EVP_PKEY_assign_EC_KEY(pkey, ec))
	{
		goto err;
	}

	ec = NULL;
err:
	if(ctx)
	{
		BN_CTX_free(ctx);
	}

	if(ec)
	{
		EC_KEY_free(ec);
	}

	return pkey;
}


typedef struct GMECC512SIGN_DATA_st
{	
	ASN1_INTEGER	*r;
	ASN1_INTEGER	*s;
}GMECC512SIGN_DATA;

DECLARE_ASN1_FUNCTIONS(GMECC512SIGN_DATA)
ASN1_SEQUENCE(GMECC512SIGN_DATA) ={		
	ASN1_SIMPLE(GMECC512SIGN_DATA, r, ASN1_INTEGER),
	ASN1_SIMPLE(GMECC512SIGN_DATA, s, ASN1_INTEGER)
}

ASN1_SEQUENCE_END(GMECC512SIGN_DATA)
	IMPLEMENT_ASN1_FUNCTIONS(GMECC512SIGN_DATA)


unsigned int GMECC512SignAsn1Convert(
	unsigned char *pbR, unsigned int nRLen,
	unsigned char *pbS, unsigned int nSLen,
	unsigned char *pbOutDer, unsigned int *pOutDerLen) 
{	
	unsigned long			nOutLen = 0;
	unsigned long			nRet = 0;

	unsigned char *p = NULL;
	unsigned char pbOut[2048] = {0};
	unsigned char *pOut = pbOut;

	GMECC512SIGN_DATA  stData;

	ASN1_INTEGER *asn1_integer_r = NULL;
	ASN1_INTEGER *asn1_integer_s = NULL;
	BIGNUM	*bNUM = NULL;

	//r
	p = pbR;
	bNUM = BN_bin2bn(p, nRLen, NULL);
	if(NULL == bNUM)
	{
		nRet = -1;
		goto ErrExit;
	}
	asn1_integer_r = BN_to_ASN1_INTEGER(bNUM, NULL);
	if(NULL == asn1_integer_r)
	{
		nRet = -2;
		goto ErrExit;
	}

	if(bNUM)
		BN_free(bNUM);

	//s
	p = pbS;
	bNUM = BN_bin2bn(p, nSLen, NULL);
	if(NULL == bNUM)
	{
		nRet = -1;
		goto ErrExit;
	}
	asn1_integer_s = BN_to_ASN1_INTEGER(bNUM, NULL);
	if(NULL == asn1_integer_s)
	{
		nRet = -2;
		goto ErrExit;
	}

	if(bNUM)
		BN_free(bNUM);

	//	
	stData.r = asn1_integer_r;
	stData.s = asn1_integer_s;
	nOutLen = i2d_GMECC512SIGN_DATA(&stData, &pOut);

	*pOutDerLen = nOutLen;

	if(pbOutDer)
		memcpy(pbOutDer, pbOut, nOutLen);

ErrExit:	

	return nRet;
}

unsigned int GMECC512SignAsn1DeConvert(
	unsigned char *pbR, unsigned int *nRLen,
	unsigned char *pbS, unsigned int *nSLen,
	unsigned char *pbDer, unsigned int nDerLen) 
{	
	unsigned int 		nOutLen = 0;
	unsigned long		nRet = 0;

	unsigned char * pPtr = pbDer;

	GMECC512SIGN_DATA  * stData = d2i_GMECC512SIGN_DATA(NULL, &pPtr,nDerLen);

	BIGNUM	*bNUM = NULL;

	if(NULL == stData)
	{
		nRet = -2;
		goto ErrExit;
	}

	bNUM = ASN1_INTEGER_to_BN(stData->r, NULL);
	if(NULL == bNUM)
	{
		nRet = -1;
		goto ErrExit;
	}
	*nRLen = BN_bn2bin(bNUM,pbR);

	if(bNUM)
	{
		BN_free(bNUM);
	}

	bNUM = ASN1_INTEGER_to_BN(stData->s, NULL);
	if(NULL == bNUM)
	{
		nRet = -1;
		goto ErrExit;
	}
	*nSLen = BN_bn2bin(bNUM,pbS);

	if(bNUM)
	{
		BN_free(bNUM);
	}

ErrExit:	

	return nRet;
}

unsigned int OpenSSL_GMECC512GenKeys(unsigned char * pbPublicKeyX,  unsigned int * puiPublicKeyXLen, 
	unsigned char * pbPublicKeyY,  unsigned int * puiPublicKeyYLen,
	unsigned char * pbPrivateKey,  unsigned int * puiPrivateKeyLen)
{
	EC_KEY		*ec = NULL;
	unsigned long		rv	= -1;

	BN_CTX *ctx=NULL;
	EC_POINT *pubkey=NULL;
	BIGNUM *pubkey_x=NULL, *pubkey_y=NULL,*prvkey=NULL;

	unsigned char data_value_x[GM_ECC_512_BYTES_LEN]= {0};
	unsigned char data_value_y[GM_ECC_512_BYTES_LEN]= {0};
	unsigned char data_value_prv[GM_ECC_512_BYTES_LEN]= {0};
	unsigned int data_len_x = GM_ECC_512_BYTES_LEN;
	unsigned int data_len_y = GM_ECC_512_BYTES_LEN;
	unsigned int data_len_prv = GM_ECC_512_BYTES_LEN;

	if ( !(ctx = BN_CTX_new()) )
	{
		goto err;
	}

	ec = EC_KEY_new();
	if (NULL==ec)
	{
		goto err;
	}

	if ( !(EC_KEY_set_group(ec, g_group512)) )
	{
		goto err;
	}

	if (!EC_KEY_generate_key(ec))
	{
		goto err;
	}

	if (!EC_KEY_check_key(ec)) 
	{
		goto err;
	}

	prvkey = (BIGNUM *)EC_KEY_get0_private_key(ec);
	pubkey = (EC_POINT*)EC_KEY_get0_public_key(ec);

	pubkey_x= BN_new();
	pubkey_y= BN_new();

	EC_POINT_get_affine_coordinates_GFp(g_group512,pubkey,pubkey_x,pubkey_y,ctx);
	data_len_x = BN_bn2bin(pubkey_x, data_value_x);
	data_len_y = BN_bn2bin(pubkey_y,data_value_y);
	data_len_prv = BN_bn2bin(prvkey,data_value_prv);

	if(* puiPublicKeyYLen < GM_ECC_512_BYTES_LEN || * puiPublicKeyXLen <GM_ECC_512_BYTES_LEN || *puiPrivateKeyLen < GM_ECC_512_BYTES_LEN)
	{
		rv = -1;
		goto err;
	}
	else
	{
		*puiPublicKeyYLen = GM_ECC_512_BYTES_LEN;
		*puiPublicKeyXLen = GM_ECC_512_BYTES_LEN;
		*puiPrivateKeyLen = GM_ECC_512_BYTES_LEN;

		memcpy(pbPublicKeyX,data_value_x,data_len_x);
		memcpy(pbPublicKeyY,data_value_y,data_len_y);
		memcpy(pbPrivateKey,data_value_prv,data_len_prv);
	}

	rv = 0;
err:
	if(ec)
	{
		EC_KEY_free(ec);
	}

	if(ctx)
	{
		BN_CTX_free(ctx);
	}

	return rv;
}

unsigned int OpenSSL_GMECC512VerifyCert(const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
	const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen)
{
	unsigned int rv = -1;
	X509 * x509 =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int uiSigLen = BUFFER_LEN_1K;

	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;

	unsigned int r_len = GM_ECC_512_BYTES_LEN;
	unsigned int s_len = GM_ECC_512_BYTES_LEN;

	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	ptr_in = pbX509Cert;
	x509 = d2i_X509(NULL, &ptr_in, uiX509CertLen);
	if (NULL == x509)
	{
		goto err;
	}
	

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	rv = GMECC512SignAsn1DeConvert(pbSig,&r_len,pbSig+ GM_ECC_512_BYTES_LEN,&s_len,x509->signature->data,x509->signature->length);
	if(rv)
	{
		goto err;
	}

	//rv = OpenSSL_VerifyMSG(cert_buffer_data,cert_buffer_len, sig,2 * GM_ECC_512_BYTES_LEN,pbPublicKeyX,GM_ECC_512_BYTES_LEN,pbPublicKeyY,GM_ECC_512_BYTES_LEN);

	info_len =i2d_X509_CINF(x509->cert_info,&ptr_out);

	//ASN1_item_i2d(cer->cert_info,&pCert,ASN1_ITEM_rptr(X509_CINF));

	rv = tcm_gmecc512_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if(rv)
	{
		goto err;
	}

	rv = OpenSSL_GMECC512VerifyDigest(digest_value,digest_len, pbSig,2 * GM_ECC_512_BYTES_LEN,pbPublicKeyX,GM_ECC_512_BYTES_LEN,pbPublicKeyY,GM_ECC_512_BYTES_LEN);
	if(rv)
	{
		goto err;
	}
err:

	if (x509)
	{
		X509_free(x509);
	}

	return rv;
}


unsigned int OpenSSL_GMECC512VerifyCRL(const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
	const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen)
{
	unsigned int rv = -1;
	X509_CRL * crl =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int uiSigLen = BUFFER_LEN_1K;
	EC_KEY      * ecPubkey = NULL;

	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;

	unsigned int r_len = GM_ECC_512_BYTES_LEN;
	unsigned int s_len = GM_ECC_512_BYTES_LEN;

	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	ptr_in = pbCRL;
	crl = d2i_X509_CRL(NULL, &ptr_in, uiCRLLen);
	if (NULL == crl)
	{
		goto err;
	}

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	GMECC512SignAsn1DeConvert(pbSig,&r_len,pbSig+ GM_ECC_512_BYTES_LEN,&s_len,crl->signature->data,crl->signature->length);

	//rv = OpenSSL_VerifyMSG(cert_buffer_data,cert_buffer_len, sig,2 * GM_ECC_512_BYTES_LEN,pbPublicKeyX,GM_ECC_512_BYTES_LEN,pbPublicKeyY,GM_ECC_512_BYTES_LEN);

	info_len =i2d_X509_CRL_INFO(crl->crl,&ptr_out);

	//ASN1_item_i2d(cer->cert_info,&pCert,ASN1_ITEM_rptr(X509_CINF));

	rv = tcm_gmecc512_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if(rv)
	{
		goto err;
	}

	rv = OpenSSL_GMECC512VerifyDigest(digest_value,digest_len, pbSig,2 * GM_ECC_512_BYTES_LEN,pbPublicKeyX,GM_ECC_512_BYTES_LEN,pbPublicKeyY,GM_ECC_512_BYTES_LEN);
	if(rv)
	{
		goto err;
	}

err:

	if (crl)
	{
		X509_CRL_free(crl);
	}

	return rv;
}

unsigned int OpenSSL_GMECC512VerifyMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
	const unsigned char *pbSig, unsigned int uiSigLen,
	const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen)
{
	unsigned int rv	= -1;
	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;

	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	rv = tcm_gmecc512_get_message_hash((unsigned char *)pbMSG, uiMSGLen,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);

	if (rv)
	{
		goto err;
	}


	rv = OpenSSL_GMECC512VerifyDigest(digest_value,digest_len,pbSig,uiSigLen,pbPublicKeyX,uiPublicKeyXLen,pbPublicKeyY,uiPublicKeyYLen);
	if (rv)
	{
		goto err;
	}

err:

	return rv;
}

unsigned int OpenSSL_GMECC512VerifyCSR(
	const unsigned char *pbCSR, unsigned int uiCSRLen,
	unsigned int uiAlg
	)
{
	EVP_PKEY	*pktmp = NULL;
	X509_REQ *req = NULL;
	unsigned int rv = -1;
	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;
	unsigned char pbPublicKeyX[GM_ECC_512_BYTES_LEN] = {0};
	unsigned char pbPublicKeyY[GM_ECC_512_BYTES_LEN] = {0};
	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;

	unsigned int r_len = GM_ECC_512_BYTES_LEN;
	unsigned int s_len = GM_ECC_512_BYTES_LEN;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int uiSigLen = BUFFER_LEN_1K;

	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;

	ptr_in = pbCSR;

	req = d2i_X509_REQ(NULL, &ptr_in, uiCSRLen);
	if (NULL == req)
	{
		goto err;
	}
	
	if((pktmp=X509_REQ_get_pubkey(req)) == NULL)
	{
		//goto err;
		pktmp = OpenSSL_NewEVP_PKEY_OF_GMECC512_PublicKey(
			req->req_info->pubkey->public_key->data + 1,
			GM_ECC_512_BYTES_LEN,
			req->req_info->pubkey->public_key->data + 1 + GM_ECC_512_BYTES_LEN,
			GM_ECC_512_BYTES_LEN
			);
	}

	if (pktmp == NULL)
	{
		goto err;
	}

	ptr_out = info_value;

	info_len = i2d_X509_REQ_INFO(req->req_info, &ptr_out);

	memcpy(pubkey_xy_value, req->req_info->pubkey->public_key->data, req->req_info->pubkey->public_key->length);
	memcpy(pbPublicKeyX, pubkey_xy_value + 1, GM_ECC_512_BYTES_LEN);
	memcpy(pbPublicKeyY, pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, GM_ECC_512_BYTES_LEN);

	if (req->signature->length != 2 * GM_ECC_512_BYTES_LEN)
	{
		GMECC512SignAsn1DeConvert(pbSig,&r_len,pbSig+ GM_ECC_512_BYTES_LEN,&s_len,req->signature->data,req->signature->length);
		rv = tcm_gmecc512_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	}
	else
	{
		goto err;
	}

	if(rv)
	{
		goto err;
	}
	
	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_STRING(file_log_name, "OpenSSL..........OpenSSL_GMECC512VerifyCSR");

	FILE_LOG_STRING(file_log_name, "tcm_gmecc512_get_message_hash pbPublicKey");
	FILE_LOG_HEX(file_log_name,pubkey_xy_value, GM_ECC_512_BYTES_LEN * 2 + 1);

	FILE_LOG_STRING(file_log_name, "tcm_gmecc512_get_message_hash pbDigest");
	FILE_LOG_HEX(file_log_name,digest_value, digest_len);

	FILE_LOG_STRING(file_log_name, "tcm_gmecc512_get_message_hash m_szCsr");
	FILE_LOG_HEX(file_log_name,info_value, info_len);


	rv = OpenSSL_GMECC512VerifyDigest(digest_value,GM_ECC_512_BYTES_LEN,pbSig,2 * GM_ECC_512_BYTES_LEN,pbPublicKeyX, GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);
	if(rv)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, rv);
err:
	if(pktmp != NULL)	
	{
		EVP_PKEY_free(pktmp);
	}

	if(req)
	{
		X509_REQ_free(req);
	}

	return rv;
}

unsigned int OpenSSL_GMECC512SignCSR(
	const unsigned char *pbCSR, unsigned int uiCSRLen,
	const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
	unsigned int uiAlg,
	unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen
	)
{
	EVP_PKEY	*pktmp = NULL;			//
	X509_REQ *req = NULL;
	BN_CTX *ctx=NULL;
	EC_KEY      * ecPubkey = NULL;
	const EC_POINT	* pubkey = NULL;
	BIGNUM * pubkey_x = NULL;
	BIGNUM * pubkey_y = NULL;
	unsigned int rv = -1;
	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;
	unsigned char pbPublicKeyX[GM_ECC_512_BYTES_LEN] = {0};
	unsigned char pbPublicKeyY[GM_ECC_512_BYTES_LEN] = {0};
	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	unsigned int r_len = GM_ECC_512_BYTES_LEN;
	unsigned int s_len = GM_ECC_512_BYTES_LEN;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int uiSigLen = BUFFER_LEN_1K;

	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;

	ptr_in = pbCSR;

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_HEX(file_log_name, ptr_in, uiCSRLen);

	req = d2i_X509_REQ(NULL, &ptr_in, uiCSRLen);
	if (NULL == req)
	{
		goto err;
	}

	if ( !(ctx = BN_CTX_new()) )
	{		
		goto err;	
	}


	if((pktmp=X509_REQ_get_pubkey(req)) == NULL)
	{
		//goto err;
		pktmp = OpenSSL_NewEVP_PKEY_OF_GMECC512_PublicKey(
			req->req_info->pubkey->public_key->data + 1,
			GM_ECC_512_BYTES_LEN,
			req->req_info->pubkey->public_key->data + 1 + GM_ECC_512_BYTES_LEN,
			GM_ECC_512_BYTES_LEN
			);
	}

	if (pktmp == NULL)
	{
		goto err;
	}

	ptr_out = info_value;

	info_len = i2d_X509_REQ_INFO(req->req_info, &ptr_out);

	ecPubkey = pktmp->pkey.ec;

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ecPubkey);
	
	pubkey = (EC_POINT*)EC_KEY_get0_public_key(ecPubkey);

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, pubkey);

	pubkey_x= BN_new();
	pubkey_y= BN_new();

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_num_bytes(pubkey_x));
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_num_bytes(pubkey_y));
	


	EC_POINT_get_affine_coordinates_GFp(g_group512,pubkey,pubkey_x,pubkey_y,ctx);

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_num_bytes(pubkey_x));
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_num_bytes(pubkey_y));
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, pubkey_x);
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, pubkey_y);
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_bn2bin(pubkey_x, pbPublicKeyX));
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_bn2bin(pubkey_y, pbPublicKeyY));


	BN_bn2bin(pubkey_x, pbPublicKeyX);
	BN_bn2bin(pubkey_y, pbPublicKeyY);

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_HEX(file_log_name, pubkey_xy_value,65);

	memcpy(pubkey_xy_value, req->req_info->pubkey->public_key->data, req->req_info->pubkey->public_key->length);
	
	FILE_LOG_HEX(file_log_name, pubkey_xy_value,65);

	rv = tcm_gmecc512_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if(rv)
	{
		goto err;
	}

	rv = OpenSSL_GMECC512SignDigest(digest_value, digest_len, pbPrivateKey,uiPrivateKeyLen, pbSig,&uiSigLen);
	if(rv)
	{
		goto err;
	}
	FILE_LOG_HEX(file_log_name, pbSig,uiSigLen);
	
	FILE_LOG_HEX(file_log_name, digest_value,digest_len);
	FILE_LOG_HEX(file_log_name, pubkey_xy_value,65);
	rv = GMECC512SignAsn1Convert(pbSig,GM_ECC_512_BYTES_LEN, pbSig + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN, encode_value, &encode_len);
	FILE_LOG_STRING(file_log_name, "rv");
	FILE_LOG_NUMBER(file_log_name, rv);
	FILE_LOG_STRING(file_log_name, "encode_value");
	FILE_LOG_HEX(file_log_name, encode_value, encode_len);
	if (rv)
	{
		goto err;
	}

	ASN1_BIT_STRING_set(req->signature,encode_value, encode_len);
	req->signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	req->signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

	ptr_out = pbCSRSigned;
	*puiCSRSignedLen =  i2d_X509_REQ(req, &ptr_out);

	rv = 0;

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, rv);
err:
	if(pktmp != NULL)	
	{
		EVP_PKEY_free(pktmp);
	}

	if(req)
	{
		X509_REQ_free(req);
	}
		
	if(ctx)	
	{
		BN_CTX_free(ctx);	
	}

	return rv;
}


unsigned int OpenSSL_GMECC512SetX509SignValue(
	const unsigned char *pbX509, unsigned int uiX509Len,
	X509_TYPE uiX509Type,
	const unsigned char *pbR, unsigned int uiRLen,
	const unsigned char *pbS, unsigned int uiSLen,
	unsigned char *pbX509Signed, unsigned int * puiX509SignedLen)
{
	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};
	X509_REQ *req = NULL;
	X509 *x509 = NULL;
	X509_CRL *crl = NULL;
	unsigned int rv = -1;
	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;

	ptr_in = pbX509;
	ptr_out = pbX509Signed;

	rv = GMECC512SignAsn1Convert(pbR,GM_ECC_512_BYTES_LEN, pbS,GM_ECC_512_BYTES_LEN, encode_value, &encode_len);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"encode_value");
	FILE_LOG_HEX(file_log_name, encode_value, encode_len);
	if (rv)
	{
		goto err;
	}

	switch(uiX509Type)
	{
	case X509_TYPE_CSR:
		{
			req = d2i_X509_REQ(NULL, &ptr_in, uiX509Len);
			if (NULL == req)
			{
				goto err;
			}

			ASN1_BIT_STRING_set(req->signature,encode_value, encode_len);
			req->signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
			req->signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

			*puiX509SignedLen =  i2d_X509_REQ(req, &ptr_out);
		}
		break;
	case X509_TYPE_CERT:
		{
			x509 = d2i_X509(NULL, &ptr_in, uiX509Len);
			if (NULL == req)
			{
				goto err;
			}

			ASN1_BIT_STRING_set(x509->signature,encode_value, encode_len);
			x509->signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
			x509->signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

			*puiX509SignedLen =  i2d_X509(x509, &ptr_out);
		}
		break;
	case X509_TYPE_CRL:
		{
			crl = d2i_X509_CRL(NULL, &ptr_in, uiX509Len);
			if (NULL == req)
			{
				goto err;
			}

			ASN1_BIT_STRING_set(crl->signature,encode_value, encode_len);
			crl->signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
			crl->signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

			*puiX509SignedLen =  i2d_X509_CRL(crl, &ptr_out);
		}
		break;
	defauit:
		goto err;
		break;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"pbX509");
	FILE_LOG_HEX(file_log_name, pbX509, uiX509Len);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"pbX509Signed");
	FILE_LOG_HEX(file_log_name, pbX509Signed, *puiX509SignedLen);

	rv = 0;
err:

	if(req)
	{
		X509_REQ_free(req);
	}

	if(x509)
	{
		X509_free(x509);
	}

	if(crl)
	{
		X509_CRL_free(crl);
	}

	return rv;
}


unsigned int OpenSSL_GMECC512SignMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
	const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
	const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
	unsigned int uiAlg,
	unsigned char *pbSig, unsigned int * puiSigLen)
{
	unsigned int rv	= -1;
	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;

	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	rv = tcm_gmecc512_get_message_hash((unsigned char *)pbMSG, uiMSGLen,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if (rv)
	{
		goto err;
	}

	rv = OpenSSL_GMECC512SignDigest(digest_value, digest_len, pbPrivateKey,uiPrivateKeyLen, pbSig,puiSigLen);
	if(rv)
	{
		goto err;
	}

err:

	return rv;
}

unsigned int OpenSSL_GMECC512SignCRL(
	const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
	const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
	const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
	unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
	)
{
	unsigned int rv = -1;
	X509_CRL * crl =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int uiSigLen = BUFFER_LEN_1K;
	//EC_KEY      * ecPubkey = NULL;

	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;

	unsigned int r_len = GM_ECC_512_BYTES_LEN;
	unsigned int s_len = GM_ECC_512_BYTES_LEN;

	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	ptr_in = pbCRL;
	crl = d2i_X509_CRL(NULL, &ptr_in, uiCRLLen);
	if (NULL == crl)
	{
		goto err;
	}
	
	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	GMECC512SignAsn1DeConvert(pbSig,&r_len,pbSig+ GM_ECC_512_BYTES_LEN,&s_len,crl->signature->data,crl->signature->length);

	//rv = OpenSSL_VerifyMSG(cert_buffer_data,cert_buffer_len, sig,2 * GM_ECC_512_BYTES_LEN,pbPublicKeyX,GM_ECC_512_BYTES_LEN,pbPublicKeyY,GM_ECC_512_BYTES_LEN);

	info_len =i2d_X509_CRL_INFO(crl->crl,&ptr_out);

	//ASN1_item_i2d(cer->cert_info,&pCert,ASN1_ITEM_rptr(X509_CINF));

	rv = tcm_gmecc512_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if(rv)
	{
		goto err;
	}

	rv = OpenSSL_GMECC512SignDigest(digest_value, digest_len, pbPrivateKey,uiPrivateKeyLen, pbSig,&uiSigLen);
	if(rv)
	{
		goto err;
	}
	rv = GMECC512SignAsn1Convert(pbSig,GM_ECC_512_BYTES_LEN, pbSig + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN, encode_value, &encode_len);
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

	ptr_out = pbCRLSigned;
	*puiCRLSignedLen =  i2d_X509_CRL(crl, &ptr_out);

	rv = 0;

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, rv);

err:

	if (crl)
	{
		X509_CRL_free(crl);
	}

	return rv;
}


unsigned int OpenSSL_GMECC512SignCert(
	const unsigned char *pbX509Cert,   unsigned int uiX509CertLen, 
	const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
	const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen,
	unsigned char * pbX509CertSigned,  unsigned int *puiX509CertSignedLen
	)
{
	unsigned int rv = -1;
	X509 * x509 =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int uiSigLen = BUFFER_LEN_1K;

	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;

	unsigned int r_len = GM_ECC_512_BYTES_LEN;
	unsigned int s_len = GM_ECC_512_BYTES_LEN;

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	ptr_in = pbX509Cert;
	x509 = d2i_X509(NULL, &ptr_in, uiX509CertLen);
	if (NULL == x509)
	{
		goto err;
	}
	
	ptr_out = info_value;

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	info_len =i2d_X509_CINF(x509->cert_info,&ptr_out);

	rv = tcm_gmecc512_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);

	if (rv)
	{
		goto err;
	}

	rv = OpenSSL_GMECC512SignDigest(digest_value, digest_len, pbPrivateKey,uiPrivateKeyLen, pbSig,&uiSigLen);
	if (rv)
	{
		goto err;
	}

	rv = GMECC512SignAsn1Convert(pbSig,GM_ECC_512_BYTES_LEN, pbSig + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN, encode_value, &encode_len);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"encode_value");
	FILE_LOG_HEX(file_log_name, encode_value, encode_len);
	if (rv)
	{
		goto err;
	}

	ASN1_BIT_STRING_set(x509->signature,encode_value, encode_len);
	x509->signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	x509->signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

	ptr_out = pbX509CertSigned;
	*puiX509CertSignedLen =  i2d_X509(x509, &ptr_out);

	rv = 0;

err:

	if (x509)
	{
		X509_free(x509);
	}

	return rv;
}

unsigned int OpenSSL_GMECC512GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
	const unsigned char * pbPublicKeyX,  unsigned int uiPublicKeyXLen, 
	const unsigned char * pbPublicKeyY,  unsigned int uiPublicKeyYLen,
	unsigned char * pbCSR,  unsigned int * puiCSRLen)
{
	unsigned long		rv	= -1;
	X509_REQ	*req = NULL;
	EVP_PKEY	*pkey = NULL;
	X509_NAME	*name = NULL;

	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;

	unsigned char * ptr_tmp = NULL;

	if((req = X509_REQ_new()) == NULL)
	{
		goto err;
	}

	pkey = OpenSSL_NewEVP_PKEY_OF_GMECC512_PublicKey(
		pbPublicKeyX,
		GM_ECC_512_BYTES_LEN,
		pbPublicKeyY,
		GM_ECC_512_BYTES_LEN
		);

	if (pkey == NULL)
	{
		goto err;
	}

	X509_REQ_set_pubkey(req, pkey);

	name = X509_REQ_get_subject_name(req);
	//
	//Add_Name(name, "C", (char*)pstUserInfo->countryName, strlen(pstUserInfo->countryName));
	//Add_Name(name, "ST", (char*)pstUserInfo->stateOrProvinceName, strlen(pstUserInfo->stateOrProvinceName));
	//Add_Name(name, "L", (char*)pstUserInfo->localityName, strlen(pstUserInfo->localityName));
	//Add_Name(name, "O", (char*)pstUserInfo->organizationName, strlen(pstUserInfo->organizationName));
	//Add_Name(name, "OU", (char*)pstUserInfo->organizationalUnitName, strlen(pstUserInfo->organizationalUnitName));
	//Add_Name(name, "CN", (char*)pstUserInfo->commonName, strlen(pstUserInfo->commonName));
	//Add_Name(name, "emailAddress", (char*)pstUserInfo->emailAddress, strlen(pstUserInfo->emailAddress));
	//Add_Name(name, "challengePassword", (char*)pstUserInfo->challengePassword, strlen(pstUserInfo->challengePassword));
	//Add_Name(name, "unstructuredName", (char*)pstUserInfo->unstructuredName, strlen(pstUserInfo->unstructuredName));
	//

	OpenSSL_AddNameByName(name, "C", (unsigned char *)pstUserInfo->countryName,pstUserInfo->uiLenC,0);
	OpenSSL_AddNameByName(name, "ST", (unsigned char *)pstUserInfo->stateOrProvinceName,pstUserInfo->uiLenST,0);
	OpenSSL_AddNameByName(name, "L", (unsigned char *)pstUserInfo->localityName,pstUserInfo->uiLenL, 0);
	OpenSSL_AddNameByName(name, "O", (unsigned char *)pstUserInfo->organizationName,pstUserInfo->uiLenO, 0);
	OpenSSL_AddNameByName(name, "OU",(unsigned char *) pstUserInfo->organizationalUnitName,pstUserInfo->uiLenOU,0);
	OpenSSL_AddNameByName(name, "CN",(unsigned char *) pstUserInfo->commonName,pstUserInfo->uiLenCN,0);
	OpenSSL_AddNameByName(name, "emailAddress",(unsigned char *) pstUserInfo->emailAddress,pstUserInfo->uiLenEA,0);
	OpenSSL_AddNameByName(name, "challengePassword",(unsigned char *)pstUserInfo->challengePassword, pstUserInfo->uiLenCP, 0);
	OpenSSL_AddNameByName(name, "unstructuredName",(unsigned char *)pstUserInfo->unstructuredName,pstUserInfo->uiLenUN,0);

	ptr_out = pbCSR;

	X509_ALGOR_set0(req->req_info->pubkey->algor,
		OBJ_txt2obj("1.2.840.10045.2.1",OBJ_NAME_TYPE_PKEY_METH)
		,V_ASN1_OBJECT,OBJ_txt2obj("1.2.156.10197.1.301",OBJ_NAME_TYPE_PKEY_METH)
		);

	X509_ALGOR_set0(req->sig_alg,
		OBJ_txt2obj("1.2.156.10197.1.501",0), 
		V_ASN1_UNDEF, NULL);

	*puiCSRLen = i2d_X509_REQ(req, &ptr_out);

	rv = 0;
err:
	if(req != NULL)	
	{	
		X509_REQ_free(req);
	}

	if(pkey != NULL)
	{	
		EVP_PKEY_free(pkey);
	}

	return rv;
}

int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype, void *pval);

unsigned int OpenSSL_GMECC512GenRootCert(const unsigned char * pbCSR,unsigned int uiCSRLen,
	unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
	unsigned int uiNotBefore, unsigned int uiNotAfter, 
	unsigned char * pbX509Cert, unsigned int * puiX509CertLen)
{
	unsigned int       rv = -1;
	EVP_PKEY	*pktmp = NULL;			//
	X509		*x509 = NULL;
	X509_NAME	*name =NULL;
	X509_REQ *req = NULL;
	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;
	BIGNUM * bnSN = NULL;

	ptr_in = pbCSR;
	
	req = d2i_X509_REQ(NULL, &ptr_in, uiCSRLen);
	if (NULL == req)
	{
		goto err;
	}
	

	if((pktmp=X509_REQ_get_pubkey(req)) == NULL)
	{
		//goto err;
		pktmp = OpenSSL_NewEVP_PKEY_OF_GMECC512_PublicKey(
			req->req_info->pubkey->public_key->data + 1,
			GM_ECC_512_BYTES_LEN,
			req->req_info->pubkey->public_key->data + 1 + GM_ECC_512_BYTES_LEN,
			GM_ECC_512_BYTES_LEN
			);
	}

	if (pktmp == NULL)
	{
		goto err;
	}
	
	if ((x509=X509_new()) == NULL)
	{
		goto err;
	}

	if(NULL == (bnSN = BN_new()))
	{
		goto err;
	}

	// 设置版本x509_v3
	X509_set_version(x509,2);


	// 设置序列号
	//ASN1_INTEGER_set(X509_get_serialNumber(x509), uiSerialNumber);

	BN_bin2bn(pbSerialNumber, uiSerialNumberLen, bnSN);
	BN_to_ASN1_INTEGER(bnSN,X509_get_serialNumber(x509));


	//设置有效期
	X509_gmtime_adj(X509_get_notBefore(x509), (long)(uiNotBefore*60*60*24));
	X509_gmtime_adj(X509_get_notAfter(x509), (long)(uiNotAfter*60*60*24));

	// 设置公钥
	X509_set_pubkey(x509, pktmp);


	// subject name
	name = X509_REQ_get_subject_name(req);

	//
	X509_set_subject_name(x509, name);

	// 
	X509_set_issuer_name(x509, name);

	//���չ��Ϣ
	Add_Ext(x509, x509, NID_basic_constraints, "critical,CA:TRUE");
	Add_Ext(x509, x509, NID_subject_key_identifier, "hash");
	Add_Ext(x509, x509, NID_authority_key_identifier, "keyid:always");
	Add_Ext(x509, x509, NID_key_usage, "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,keyAgreement,keyCertSign,cRLSign");
	Add_Ext(x509, x509, NID_domainComponent, "no");	
	Add_Ext(x509, x509, NID_Domain, "no");

	//cleanup the extension code if any custom extensions have been added
	X509V3_EXT_cleanup();

	X509_ALGOR_set0(x509->cert_info->key->algor,
		OBJ_txt2obj("1.2.840.10045.2.1",OBJ_NAME_TYPE_PKEY_METH)
		,V_ASN1_OBJECT,OBJ_txt2obj("1.2.156.10197.1.301",OBJ_NAME_TYPE_PKEY_METH)
		);

	X509_ALGOR_set0(x509->sig_alg,
		OBJ_txt2obj("1.2.156.10197.1.501",0), 
		V_ASN1_UNDEF, NULL);

	X509_ALGOR_set0(x509->cert_info->signature,
		OBJ_txt2obj("1.2.156.10197.1.501",0), 
		V_ASN1_UNDEF, NULL);


	if (!pbX509Cert)
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}
	else
	{
		ptr_out = pbX509Cert;
		* puiX509CertLen = i2d_X509(x509, &ptr_out);
	}

	rv = 0;
err:
	if(req != NULL)	
	{
		X509_REQ_free(req);
	}
	if(x509 != NULL)	
	{
		X509_free(x509);
	}
	if (bnSN)
	{
		BN_free(bnSN);
	}

	return rv;
}

unsigned int OpenSSL_GMECC512GenCert(const unsigned char * pbCSR,unsigned int uiCSRLen,
	const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
	unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
	unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
	unsigned char * pbX509Cert, unsigned int * puiX509CertLen)
{
	char * strBaseKeyUsage = NULL;
	char * strExtKeyUsage = "";
	EVP_PKEY	*pktmp = NULL;			                //
	X509		*x509 = NULL , *xCAcert = NULL;			// ���ɵ�֤��
	X509_NAME	*name = NULL;
	int isCACert = 0;
	X509_REQ *req = NULL;
	unsigned int rv = -1;
	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;
	BIGNUM * bnSN = NULL;

	if (OpenSSL_GMECC512VerifyCSR(pbCSR,uiCSRLen, 0))
	{
		goto err;
	}


	xCAcert = d2i_X509(NULL,&pbX509CACert, uiX509CACertLen);

	req = d2i_X509_REQ(NULL, &pbCSR, uiCSRLen);

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	if (NULL == req)
	{
		goto err;
	}

	if(0 == uiSignFlag)
	{
		strBaseKeyUsage = "nonRepudiation,digitalSignature";
	}
	else if(1 == uiSignFlag)
	{
		strBaseKeyUsage = "keyEncipherment,dataEncipherment";
	}
	else if(2 == uiSignFlag)
	{
		strBaseKeyUsage = "dataEncipherment";
	}
	else if(3 == uiSignFlag)
	{
		strBaseKeyUsage = "keyEncipherment";
	}

	if((pktmp=X509_REQ_get_pubkey(req)) == NULL)
	{
		//goto err;
		pktmp = OpenSSL_NewEVP_PKEY_OF_GMECC512_PublicKey(
			req->req_info->pubkey->public_key->data + 1,
			GM_ECC_512_BYTES_LEN,
			req->req_info->pubkey->public_key->data + 1 + GM_ECC_512_BYTES_LEN,
			GM_ECC_512_BYTES_LEN
			);
	}

	if (pktmp == NULL)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	FILE_LOG_STRING(file_log_name, "5");

	// new x509
	if((x509 = X509_new()) == NULL)
		goto err;

	if(NULL == (bnSN = BN_new()))
	{
		goto err;
	}

	// 设置版本x509_v3
	X509_set_version(x509,2);

	// 设置序列号
	//ASN1_INTEGER_set(X509_get_serialNumber(x509), uiSerialNumber);

	BN_bin2bn(pbSerialNumber, uiSerialNumberLen, bnSN);
	BN_to_ASN1_INTEGER(bnSN,X509_get_serialNumber(x509));

	//
	X509_gmtime_adj(X509_get_notBefore(x509), (long)(uiNotBefore*60*60*24));
	X509_gmtime_adj(X509_get_notAfter(x509), (long)(uiNotAfter*60*60*24));

	FILE_LOG_STRING(file_log_name, "7");

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	//
	if(!X509_set_subject_name(x509, X509_REQ_get_subject_name(req)))
		goto err;

	// 
	if(!X509_set_issuer_name(x509, X509_get_subject_name(xCAcert)))
		goto err;

	//
	if(!X509_set_pubkey(x509, pktmp))
		goto err;

	FILE_LOG_STRING(file_log_name, "8");

	// 
	if(!copy_extensions(x509, req, EXT_COPY_ALL))
		goto err;

	// Note if the CA option is false the pathlen option shouid be omitted. 
	if(isCACert == 0)
		Add_Ext(x509, x509, NID_basic_constraints, "critical,CA:FALSE,pathlen:1");
	else if(isCACert == 1)
		Add_Ext(x509, x509, NID_basic_constraints, "critical,CA:TRUE,pathlen:1");

	//
	Add_Ext(x509, x509, NID_subject_key_identifier, "hash");

	//Authority
	Add_Ext(x509, xCAcert, NID_authority_key_identifier, "keyid,issuer:always");

	FILE_LOG_STRING(file_log_name, "9");

	// 
	if(strlen(strBaseKeyUsage))
		Add_Ext(x509, x509, NID_key_usage, strBaseKeyUsage);

	if(strlen(strExtKeyUsage))
		Add_Ext(x509, x509, NID_ext_key_usage, strExtKeyUsage);

	X509_ALGOR_set0(x509->cert_info->key->algor,
		OBJ_txt2obj("1.2.840.10045.2.1",OBJ_NAME_TYPE_PKEY_METH)
		,V_ASN1_OBJECT,OBJ_txt2obj("1.2.156.10197.1.301",OBJ_NAME_TYPE_PKEY_METH)
		);

	X509_ALGOR_set0(x509->sig_alg,
		OBJ_txt2obj("1.2.156.10197.1.501",0), 
		V_ASN1_UNDEF, NULL);

	X509_ALGOR_set0(x509->cert_info->signature,
		OBJ_txt2obj("1.2.156.10197.1.501",0), 
		V_ASN1_UNDEF, NULL);

	ptr_out = pbX509Cert;

	* puiX509CertLen = i2d_X509(x509, &ptr_out);

	rv = 0;

err:

	if(pktmp != NULL)		
	{
		EVP_PKEY_free(pktmp);
	}

	if(x509 != NULL)	
	{
		X509_free(x509);
	}

	if(xCAcert != NULL)	
	{
		X509_free(xCAcert);
	}

	if(req)
	{
		X509_REQ_free(req);
	}

	if (bnSN)
	{
		BN_free(bnSN);
	}

	return rv;
}


unsigned int OpenSSL_GMECC512GenCertEX(const unsigned char * pbCSR,unsigned int uiCSRLen,
	const unsigned char * pbPublicKeyX,  unsigned int uiPublicKeyXLen, 
	const unsigned char * pbPublicKeyY,  unsigned int uiPublicKeyYLen,
	const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
	unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
	unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
	unsigned char * pbX509Cert, unsigned int * puiX509CertLen)
{
	char * strBaseKeyUsage = NULL;
	char * strExtKeyUsage = "";
	EVP_PKEY	*pktmp = NULL;			//
	X509		*x509 = NULL , *xCAcert = NULL;			// ���ɵ�֤��
	X509_NAME	*name = NULL;
	int isCACert = 0;
	X509_REQ *req = NULL;
	unsigned int rv = -1;
	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;
	BIGNUM * bnSN = NULL;

	if (OpenSSL_GMECC512VerifyCSR(pbCSR,uiCSRLen, 0))
	{
		goto err;
	}

	xCAcert = d2i_X509(NULL,&pbX509CACert, uiX509CACertLen);

	req = d2i_X509_REQ(NULL, &pbCSR, uiCSRLen);

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	if (NULL == req)
	{
		goto err;
	}

	if(0 == uiSignFlag)
	{
		strBaseKeyUsage = "nonRepudiation,digitalSignature";
	}
	else if(1 == uiSignFlag)
	{
		strBaseKeyUsage = "keyEncipherment,dataEncipherment";
	}
	else if(2 == uiSignFlag)
	{
		strBaseKeyUsage = "dataEncipherment";
	}
	else if(3 == uiSignFlag)
	{
		strBaseKeyUsage = "keyEncipherment";
	}


	if((pktmp=OpenSSL_NewEVP_PKEY_OF_GMECC512_PublicKey(pbPublicKeyX,uiPublicKeyXLen,pbPublicKeyY,uiPublicKeyYLen)) == NULL)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	// new x509
	if((x509 = X509_new()) == NULL)
	{
		goto err;
	}

	if(NULL == (bnSN = BN_new()))
	{
		goto err;
	}

	// 设置版本x509_v3
	X509_set_version(x509,2);

	// 设置序列号
	//ASN1_INTEGER_set(X509_get_serialNumber(x509), uiSerialNumber);

	BN_bin2bn(pbSerialNumber, uiSerialNumberLen, bnSN);
	BN_to_ASN1_INTEGER(bnSN,X509_get_serialNumber(x509));

	//
	X509_gmtime_adj(X509_get_notBefore(x509), (long)(uiNotBefore*60*60*24));
	X509_gmtime_adj(X509_get_notAfter(x509), (long)(uiNotAfter*60*60*24));

	FILE_LOG_STRING(file_log_name, "7");

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	//
	if(!X509_set_subject_name(x509, X509_REQ_get_subject_name(req)))
		goto err;

	// 
	if(!X509_set_issuer_name(x509, X509_get_subject_name(xCAcert)))
		goto err;

	//
	if(!X509_set_pubkey(x509, pktmp))
		goto err;

	FILE_LOG_STRING(file_log_name, "8");

	// 
	if(!copy_extensions(x509, req, EXT_COPY_ALL))
		goto err;

	// Note if the CA option is false the pathlen option shouid be omitted. 
	if(isCACert == 0)
		Add_Ext(x509, x509, NID_basic_constraints, "critical,CA:FALSE,pathlen:1");
	else if(isCACert == 1)
		Add_Ext(x509, x509, NID_basic_constraints, "critical,CA:TRUE,pathlen:1");

	//
	Add_Ext(x509, x509, NID_subject_key_identifier, "hash");

	//Authority
	Add_Ext(x509, xCAcert, NID_authority_key_identifier, "keyid,issuer:always");

	FILE_LOG_STRING(file_log_name, "9");

	// 
	if(strlen(strBaseKeyUsage))
		Add_Ext(x509, x509, NID_key_usage, strBaseKeyUsage);

	if(strlen(strExtKeyUsage))
		Add_Ext(x509, x509, NID_ext_key_usage, strExtKeyUsage);

	X509_ALGOR_set0(x509->cert_info->key->algor,
		OBJ_txt2obj("1.2.840.10045.2.1",OBJ_NAME_TYPE_PKEY_METH)
		,V_ASN1_OBJECT,OBJ_txt2obj("1.2.156.10197.1.301",OBJ_NAME_TYPE_PKEY_METH)
		);

	X509_ALGOR_set0(x509->sig_alg,
		OBJ_txt2obj("1.2.156.10197.1.501",0), 
		V_ASN1_UNDEF, NULL);

	X509_ALGOR_set0(x509->cert_info->signature,
		OBJ_txt2obj("1.2.156.10197.1.501",0), 
		V_ASN1_UNDEF, NULL);

	ptr_out = pbX509Cert;

	* puiX509CertLen = i2d_X509(x509, &ptr_out);

	rv = 0;

err:

	if(pktmp != NULL)		
	{
		EVP_PKEY_free(pktmp);
	}

	if(x509 != NULL)	
	{
		X509_free(x509);
	}

	if(xCAcert != NULL)	
	{
		X509_free(xCAcert);
	}

	if(req)
	{
		X509_REQ_free(req);
	}

	if (bnSN)
	{
		BN_free(bnSN);
	}

	return rv;
}

unsigned int OpenSSL_GMECC512SignDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
	const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen,
	unsigned char *pbSig, unsigned int * puiSigLen
	)
{
	unsigned int rv = -1;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL, *r = NULL, *order = NULL, *order2 = NULL, *x1 = NULL, *s = NULL;
	BIGNUM *bnOne = NULL, *bnDigest = NULL, *bnPrikey = NULL , *bnTemp = NULL;
	EC_POINT *tmp_point = NULL;
	unsigned char bR[GM_ECC_512_BYTES_LEN], bS[GM_ECC_512_BYTES_LEN];
	int rLen, sLen;

	if(!g_group512)
	{
		rv = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!pbHash || 0==uiHashLen || !pbPrivateKey || 0==uiPrivateKeyLen || !puiSigLen)
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	if(NULL == pbSig)
	{
		*puiSigLen = 2 * GM_ECC_512_BYTES_LEN;
		rv = 0;    // OK
		goto err;
	}
	if(*puiSigLen < 2 * GM_ECC_512_BYTES_LEN)
	{
		*puiSigLen = 2 * GM_ECC_512_BYTES_LEN;
		rv = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	ctx = BN_CTX_new();
	if(!ctx)
	{
		rv = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	BN_CTX_start(ctx);

	k = BN_CTX_get(ctx);
	r = BN_CTX_get(ctx);
	order = BN_CTX_get(ctx);
	order2 = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	s = BN_CTX_get(ctx);
	bnDigest = BN_CTX_get(ctx);
	bnPrikey = BN_CTX_get(ctx);
	bnTemp = BN_CTX_get(ctx);
	bnOne = BN_CTX_get(ctx);
	if (!k || !r || !order || !order2 || !x1 || !s || !bnDigest || !bnPrikey || !bnTemp || !bnOne) 
	{
		rv = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	BN_bin2bn(pbHash, uiHashLen, bnDigest);    // get bnDigest
	BN_bin2bn(pbPrivateKey, uiPrivateKeyLen, bnPrikey);	// get bnPrikey
	BN_one(bnOne);    //  bnOne = 1;

	tmp_point = EC_POINT_new(g_group512);
	if (!tmp_point)
	{
		rv = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	// get order
	if (!EC_GROUP_get_order(g_group512, order, ctx))
	{
		rv = -1;
		goto err;
	}

	while(1){
		// generate random k
		do{
			if (!BN_rand_range(k, order)) 
			{
				rv = -1;
				goto err;
			} 
		}while (BN_is_zero(k));

		// tmp_point = [k]G
		if (!EC_POINT_mul(g_group512, tmp_point, k, NULL, NULL, ctx)) 
		{
			rv = -1;
			goto err;
		}
		if (!EC_POINT_get_affine_coordinates_GFp(g_group512, tmp_point, x1, NULL, ctx))
		{
			rv = -1;
			goto err;
		}
		// r = (bnDigest + x1) mod order
		if (!BN_mod_add(r, x1, bnDigest, order, ctx)) 
		{
			rv = -1;
			goto err;
		}

		if(BN_is_zero(r))
			continue;
		// r + k = order ?
		if (!BN_add(order2, r, k)) 
		{
			rv = -1;
			goto err;
		}
		if( 0 == BN_ucmp(order, order2) )
			continue;

		// bnTemp = bnPrikey + 1 mod order
		if (!BN_mod_add(bnTemp, bnPrikey, bnOne, order, ctx)) 
		{
			rv = -1;
			goto err;
		}
		// bnTemp = (bnPrikey + 1)^{-1} mod order
		if (!BN_mod_inverse(bnTemp, bnTemp, order, ctx))
		{
			rv = -1;
			goto err;
		}

		// s = r*bnPrikey mod order
		if (!BN_mod_mul(s, bnPrikey, r, order, ctx)) 
		{
			rv = -1;
			goto err;
		}
		// s = (k - r*bnPrikey) mod order
		if (!BN_mod_sub(s, k, s, order, ctx)) 
		{
			rv = -1;
			goto err;
		}
		// s = ((bnPrikey + 1)^{-1}) * (k - r*bnPrikey) mod order
		if (!BN_mod_mul(s, bnTemp, s, order, ctx)) 
		{
			rv = -1;
			goto err;
		}

		if(BN_is_zero(s))
			continue;

		break;
	}

	rLen=BN_bn2bin(r,bR);
	sLen=BN_bn2bin(s,bS);

	// return value
	memset(pbSig, 0x00,  2 * GM_ECC_512_BYTES_LEN);
	memcpy(pbSig + GM_ECC_512_BYTES_LEN - rLen, bR, rLen);
	memcpy(pbSig + 2*GM_ECC_512_BYTES_LEN - sLen, bS, sLen);
	*puiSigLen = 2 * GM_ECC_512_BYTES_LEN;

	if (tmp_point)
		EC_POINT_free(tmp_point);
	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return 0;
err:
	if (tmp_point)
		EC_POINT_free(tmp_point);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return rv;
}


unsigned int OpenSSL_GMECC512VerifyDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
	const unsigned char *pbSig, unsigned int uiSigLen,
	const unsigned char *aPubkeyValueX, unsigned int uiPublicKeyXLen,
	const unsigned char *aPubkeyValueY, unsigned int uiPublicKeyYLen)
{
	unsigned int rv = -1;
	BN_CTX *ctx = NULL;
	BIGNUM *t = NULL, *r = NULL, *r2 = NULL, *order = NULL, *x1 = NULL, *s = NULL;
	BIGNUM *bnDigest = NULL;
	EC_POINT *pubkey = NULL, *point = NULL;
	unsigned char *bR, *bS;   // bR, bS needn't free
	EC_GROUP * group = g_group512;
	BIGNUM *pubkey_x = NULL, * pubkey_y = NULL; 

	if(!group)
	{
		rv = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!pbHash || 0==uiHashLen 
		|| !pbSig || ((2*GM_ECC_512_BYTES_LEN)!=uiSigLen)
		|| !aPubkeyValueX || 0==uiPublicKeyXLen
		|| !aPubkeyValueY || 0==uiPublicKeyYLen)
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	ctx = BN_CTX_new();
	if(!ctx)
	{
		rv = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	BN_CTX_start(ctx);

	t = BN_CTX_get(ctx);
	r = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);
	order = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	s = BN_CTX_get(ctx);
	bnDigest = BN_CTX_get(ctx);
	if (!t || !r || !r2 || !order || !x1 || !s || !bnDigest) 
	{
		rv = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	BN_bin2bn(pbHash, uiHashLen, bnDigest);    // get bnDigest

	bR=(unsigned char *)pbSig;
	bS=(unsigned char *)pbSig+GM_ECC_512_BYTES_LEN;

	BN_bin2bn(bR, GM_ECC_512_BYTES_LEN, r);
	BN_bin2bn(bS, GM_ECC_512_BYTES_LEN, s);

	// get order
	if (!EC_GROUP_get_order(group, order, ctx))
	{
		rv = -1;
		goto err;
	}

	// check r in [1, order-1], s in [1, order-1]
	if (BN_is_zero(r) || BN_is_negative(r) || BN_ucmp(r, order) >= 0 ||
		BN_is_zero(s) || BN_is_negative(s) || BN_ucmp(s, order) >= 0) 
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	// t = (r + s) mod order
	if (!BN_mod_add(t, r, s, order, ctx)) 
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}
	if(BN_is_zero(t))
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	pubkey = EC_POINT_new(group);
	point = EC_POINT_new(group);
	if (!pubkey || !point)
	{
		rv = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}


	/* set public key */
	pubkey_x = BN_bin2bn( aPubkeyValueX,uiPublicKeyXLen, NULL );
	if (NULL == pubkey_x)
	{
		goto err;
	} 

	pubkey_y = BN_bin2bn( aPubkeyValueY,uiPublicKeyYLen, NULL );
	if ( NULL == pubkey_y)
	{
		goto err;
	} 

	EC_POINT_set_affine_coordinates_GFp(g_group512,pubkey,pubkey_x,pubkey_y,ctx);

	// point = [s]G + [t]ptPubkey
	if (!EC_POINT_mul(group, point, s, pubkey, t, ctx)) 
	{
		rv = -1;
		goto err;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(group, point, x1, NULL, ctx))
	{
		rv = -1;
		goto err;
	}

	// r2 = (bnDigest + x1) mod order
	if (!BN_mod_add(r2, bnDigest, x1, order, ctx)) 
	{
		rv = -1;
		goto err;
	}

	if(0 != BN_ucmp(r, r2))
	{
		rv = OPE_ERR_VERIFY_CSR;
		goto err;
	}

	rv = 0;
err:
	if (pubkey)
		EC_POINT_free(pubkey);
	if (point)
		EC_POINT_free(point);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return rv;
}

#ifdef WIN32
#undef X509_NAME
typedef struct X509_name_st X509_NAME;
#endif

unsigned int OpenSSL_GMECC512GenCRL(const OPST_CRL * pstCRLList, unsigned int uiCRLListSize, 
	const unsigned char * pbX509Cert,unsigned int uiX509CertLen, 
	unsigned char * pbCRL, unsigned int * puiCRLLen) 
{
	unsigned int rv = -1;
	long crldays = 10;
	long crlhours = 0;
	long crlsec = 0;
	X509_CRL *crl = NULL;
	X509_REVOKED *r[COUNT_1K] = {NULL};
	ASN1_TIME *tmptm;
	X509 * x509 =  NULL;
	unsigned char * out_ptr = pbCRL;
	const unsigned char * in_ptr = pbX509Cert;
	unsigned int i = 0;
	ASN1_TIME * prevtm[COUNT_1K] = {NULL};
	ASN1_ENUMERATED *rtmp[COUNT_1K] = {NULL};
	ASN1_INTEGER * tmpser[COUNT_1K] = {NULL};
	BIGNUM * bnSN = NULL;

	crl = X509_CRL_new();

	if (NULL == crl)
	{
		goto err;
	}

	x509 = d2i_X509(NULL ,&in_ptr,uiX509CertLen );
	if (NULL == x509)
	{
		goto err;
	}

	if(NULL == (bnSN = BN_new()))
	{
		goto err;
	}

	if (!X509_CRL_set_issuer_name(crl, X509_get_subject_name(x509)))
	{
		goto err;
	}
	printf("set issuer name\n");

	tmptm = ASN1_TIME_new();
	if (!tmptm)
		goto err;
	X509_gmtime_adj(tmptm, 0);
	X509_CRL_set_lastUpdate(crl, tmptm);
	printf("set last update time\n");

	//if (!X509_time_adj(tmptm, (crldays * 24 + crlhours) * 60 * 60 + crlsec, NULL)) {
	//	printf("error setting CRL nextUpdate\n");
	//	goto err;
	//}
	//X509_CRL_set_nextUpdate(crl, tmptm);
	printf("set next update time\n");

	ASN1_TIME_free(tmptm);

	for (i = 0; i < uiCRLListSize; i++) 
	{
		prevtm[i] = ASN1_UTCTIME_new();
		rtmp[i] = ASN1_ENUMERATED_new();
		tmpser[i] = ASN1_INTEGER_new();
		r[i] = X509_REVOKED_new();

		if (NULL == prevtm[i] || NULL == rtmp[i] || NULL == r[i] || NULL == tmpser[i])
		{
			goto err;
		}

		//
		ASN1_UTCTIME_set(prevtm[i], pstCRLList[i].dt);

		if (!X509_REVOKED_set_revocationDate(r[i], prevtm[i]))
		{
			goto err;
		}

		// 
		if (!ASN1_ENUMERATED_set(rtmp[i], pstCRLList[i].reason_code))
		{
			goto err;
		}

		if (!X509_REVOKED_add1_ext_i2d(r[i], NID_crl_reason, rtmp[i], 0, 0))
		{
			goto err;
		}

		// 设置序列号

		BN_bin2bn(pstCRLList[i].sn, pstCRLList[i].snlen, bnSN);
		BN_to_ASN1_INTEGER(bnSN,tmpser[i]);

		//ASN1_INTEGER_set(tmpser[i],pstCRLList[i].sn);

		X509_REVOKED_set_serialNumber(r[i], tmpser[i]);

		X509_CRL_add0_revoked(crl, r[i]);
	}

	/* sort the data so it will be written in serial
	* number order */
	X509_CRL_sort(crl);

	printf("load the certificates private key\n");

	//if (!X509_CRL_sign(crl, pkey, EVP_ecdsa()))
	//	goto err;
	//printf("sign crl\n");

	X509_ALGOR_set0(crl->sig_alg,
		OBJ_txt2obj("1.2.156.10197.1.501",0), 
		V_ASN1_UNDEF, 0);
	X509_ALGOR_set0(crl->crl->sig_alg,
		OBJ_txt2obj("1.2.156.10197.1.501",0), 
		V_ASN1_UNDEF, 0);

	*puiCRLLen = i2d_X509_CRL(crl, &out_ptr);

	rv = 0;
err: 

	if (x509)
	{
		X509_free(x509);
	}


	if (bnSN)
	{
		BN_free(bnSN);
	}

	for (i = 0; i < uiCRLListSize; i++) 
	{
		ASN1_INTEGER_free(tmpser[i]);
		ASN1_ENUMERATED_free(rtmp[i]);
		ASN1_UTCTIME_free(prevtm[i]);
		//X509_REVOKED_free(r[i]);
		r[i] = NULL;
	}

	if (crl)
	{
		X509_CRL_free(crl);
	}

	return rv;
}

unsigned int OpenSSL_GMECC512Decrypt(const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen, const unsigned char * pbIN, unsigned int uiINLen,
	unsigned char * pbOUT, unsigned int * puiOUTLen)
{
	unsigned char * szData = NULL;
	unsigned int szLen = BUFFER_LEN_1K * BUFFER_LEN_1K;
	unsigned int uiRet = -1;

	if(!pbIN || !pbPrivateKey)
	{
		return -1;
	}


	uiRet = OpenSSL_GMECC512DecryptInner((unsigned char *)pbIN, uiINLen, (unsigned char *)pbPrivateKey, uiPrivateKeyLen, szData, &szLen);

	if(uiRet)
	{
		goto err;
	}

	szData = malloc(szLen);
	memset(szData, 0, szLen);

	uiRet = OpenSSL_GMECC512DecryptInner((unsigned char *)pbIN, uiINLen, (unsigned char *)pbPrivateKey, uiPrivateKeyLen, szData, &szLen);

	if (uiRet)
	{
		goto err;
	}
	
	* puiOUTLen = szLen;

	if (NULL == pbOUT || * puiOUTLen < szLen)
	{

	}
	else
	{
		memcpy(pbOUT,szData,szLen);
	}


err:

	if (szData)
	{
		free(szData);
	}
	
	return uiRet;
}

unsigned int OpenSSL_GMECC512Encrypt(const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
	const unsigned char * pbIN, unsigned int uiINLen,
	unsigned char * pbOUT, unsigned int * puiOUTLen)
{
	unsigned char * szData = NULL;
	unsigned int szLen = BUFFER_LEN_1K * BUFFER_LEN_1K;
	unsigned int uiRet = -1;

	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	if(!pbIN || !pbPublicKeyX || !pbPublicKeyY)
	{
		return -1;
	}

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	//uiRet = gm_hash_ecc_encrypt((unsigned char *)pbIN, uiINLen, (unsigned char *)pubkey_xy_value, pubkey_xy_len, szData, &szLen);
	uiRet = OpenSSL_GMECC512EncryptInner(pbIN,uiINLen,pbPublicKeyX,uiPublicKeyXLen,pbPublicKeyY,uiPublicKeyYLen,szData,&szLen);

	if(uiRet)
	{
		goto err;
	}

	szData = malloc(szLen);
	memset(szData, 0, szLen);

	//uiRet = gm_hash_ecc_encrypt((unsigned char *)pbIN, uiINLen, (unsigned char *)pubkey_xy_value, pubkey_xy_len, szData, &szLen);
	uiRet = OpenSSL_GMECC512EncryptInner(pbIN,uiINLen,pbPublicKeyX,uiPublicKeyXLen,pbPublicKeyY,uiPublicKeyYLen,szData,&szLen);

	if (uiRet)
	{
		goto err;
	}

	* puiOUTLen = szLen;

	if (NULL == pbOUT || * puiOUTLen < szLen)
	{

	}
	else
	{
		memcpy(pbOUT,szData,szLen);
	}
	
err:

	if (szData)
	{
		free(szData);
	}

	return uiRet;
}




unsigned int OpenSSL_GMECC512Point(const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen
	)
{
	unsigned int uiRet = 0;
	unsigned char data_value[GM_ECC_512_BYTES_LEN * 2 +1] = {0};

	data_value[0] = 0x04;

	memcpy(data_value + 1,pbPublicKeyX, uiPublicKeyXLen);
	memcpy(data_value + 1 + uiPublicKeyXLen,pbPublicKeyY, uiPublicKeyYLen);

	if (tcm_gmecc512_is_point_valid(data_value,sizeof(data_value)))
	{
		uiRet = 0;
	}
	else
	{
		uiRet = -1;
	}

	return uiRet;
}


unsigned int OpenSSL_GMECC512Write(const unsigned char * pbIN, unsigned int uiINLen, 
	unsigned int uiType,char * szFileName,unsigned int fileEncode, char * szPassword
	)
{
	unsigned int uiRet = -1;

	FILE * file = fopen(szFileName, "w");

	if(NULL == file)
	{
		goto err;
	}

	switch(uiType)
	{
	case E_INPUT_DATA_TYPE_PRIVATEKEY:
		{
			EVP_PKEY * pkey = NULL;
			EC_KEY		*ec = NULL;
			BN_CTX *ctx=NULL;
			BIGNUM *prvkey=NULL;
			unsigned char data_value[BUFFER_LEN_1K * 4] = {0};
			unsigned int data_len = BUFFER_LEN_1K *4;
			unsigned char * ptr_out = NULL;

			if(uiINLen != GM_ECC_512_BYTES_LEN)
			{
				uiRet = -1;
				goto err;
			}

			if((pkey = EVP_PKEY_new()) == NULL)
			{
				goto err;
			}

			if ( !(ctx = BN_CTX_new()) )
			{
				goto err;
			}

			ec = EC_KEY_new();
			if (NULL==ec)
			{
				goto err;
			}

			if (!(EC_KEY_set_group(ec, g_group512)))
			{
				goto err;
			}

			if (!EC_KEY_generate_key(ec))
			{
				goto err;
			}

			/* set private key */
			prvkey = BN_bin2bn( pbIN,uiINLen, NULL );
			if (NULL == prvkey)
			{
				goto err;
			} 

			if ( !EC_KEY_set_private_key(ec, prvkey))
			{
				goto err;
			} 
			//// NO PRIVKEY
			//if (!EC_KEY_check_key(ec)) 
			//{
			//	goto err;
			//}

			if(!EVP_PKEY_assign_EC_KEY(pkey, ec))
			{
				goto err;
			}

			// 写入文件
			if(fileEncode == EFILEENCODE_TYPE_DER)
			{
				ptr_out = data_value;

				data_len = i2d_PrivateKey(pkey, &ptr_out);

				fwrite(data_value,data_len,1,file);
			}
			else if(fileEncode == EFILEENCODE_TYPE_PEM)
			{
				if(strlen(szPassword) == 0)
				{
					data_len = PEM_write_PrivateKey(file, pkey, NULL, NULL, 0, NULL, NULL);
				}
				else
				{
					EVP_CIPHER *cipher=NULL;
					cipher = (EVP_CIPHER *)EVP_des_ede3_cbc();
					data_len = PEM_write_PrivateKey(file, pkey, cipher, (unsigned char*)szPassword, strlen(szPassword), NULL, NULL);
				}
				
			}
			uiRet = 0;
		}
		break;
	case E_INPUT_DATA_TYPE_CERT:
		{
			X509 * x509 = NULL;
			const unsigned char * ptr_in = NULL;
			unsigned char data_value[BUFFER_LEN_1K * 4] = {0};
			unsigned int data_len = BUFFER_LEN_1K *4;
			unsigned char * ptr_out = NULL;

			ptr_in = pbIN;

			x509 = d2i_X509(NULL,&ptr_in,uiINLen);

			if (NULL == x509)
			{
				goto err;
			}
			
			if(fileEncode == EFILEENCODE_TYPE_DER)
			{
				ptr_out = data_value;
				data_len = i2d_X509(x509,&ptr_out);
				fwrite(data_value,data_len,1,file);
			}
			else if(fileEncode == EFILEENCODE_TYPE_PEM)
			{
				data_len = PEM_write_X509(file, x509);
				
			}
			uiRet = 0;
		}
		break;

	case E_INPUT_DATA_TYPE_PUBLICKEY:
		{
			const unsigned char * ptr_in = NULL;
			unsigned char data_value[BUFFER_LEN_1K * 4] = {0};
			unsigned int data_len = BUFFER_LEN_1K *4;
			unsigned char * ptr_out = NULL;
			EVP_PKEY * pkey = NULL;
			EC_KEY		*ec = NULL;
			BN_CTX *ctx=NULL;
			EC_POINT *pubkey=NULL;
			BIGNUM *pubkey_x=NULL, *pubkey_y=NULL;

			if(uiINLen != GM_ECC_512_BYTES_LEN * 2)
			{
				uiRet = -1;
				goto err;
			}

			if((pkey = EVP_PKEY_new()) == NULL)
			{
				goto err;
			}

			if ( !(ctx = BN_CTX_new()) )
			{
				goto err;
			}

			ec = EC_KEY_new();
			if (NULL==ec)
			{
				goto err;
			}

			if (!(EC_KEY_set_group(ec, g_group512)))
			{
				goto err;
			}

			if (!(pubkey = EC_POINT_new(g_group512)))
			{ 
				goto err;
			}

			if (!EC_KEY_generate_key(ec))
			{
				goto err;
			}

			/* set public key */
			pubkey_x = BN_bin2bn( pbIN,GM_ECC_512_BYTES_LEN, NULL );
			if (NULL == pubkey_x)
			{
				goto err;
			} 

			pubkey_y = BN_bin2bn( pbIN+GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN, NULL );
			if ( NULL == pubkey_y)
			{
				goto err;
			} 

			if ( !EC_POINT_set_affine_coordinates_GFp(g_group512, pubkey, pubkey_x, pubkey_y, ctx) )
			{
				goto err;
			} 

			if ( !EC_KEY_set_public_key(ec, pubkey) )
			{
				goto err;
			} 
			//// NO PRIVKEY
			//if (!EC_KEY_check_key(ec)) 
			//{
			//	goto err;
			//}

			if(!EVP_PKEY_assign_EC_KEY(pkey, ec))
			{
				goto err;
			}

			if(fileEncode == EFILEENCODE_TYPE_DER)
			{
				ptr_out = data_value;
				data_len = i2d_PUBKEY(pkey,&ptr_out);
				fwrite(data_value,data_len,1,file);
			}
			else if(fileEncode == EFILEENCODE_TYPE_PEM)
			{
				// not define
			}
			uiRet = 0;

		}
		break;
	defauit:
		break;
	}

err:
	if (file)
	{
		fclose(file);
	}
	
	return uiRet;
}



unsigned int OpenSSL_GMECC512DecryptInner(const unsigned char *pbIN, unsigned int uiINLen, 
	const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
	unsigned char *pbOUT, unsigned int * puiOUTLen)
{
	unsigned int uiRet = -1;

	unsigned int uiPlainTextLen = 0;

	unsigned char * c1 = NULL; 
	unsigned char * c2 = NULL;
	unsigned char * c3 = NULL;
	unsigned char * t = NULL;
	unsigned char * zero_buffer = NULL;
	unsigned char * data_value_out = NULL;
	unsigned char data_value_digest[(GM_HASH_BYTES_LEN)] = {0};
	unsigned int data_len_digest = (GM_HASH_BYTES_LEN);

	BIGNUM * pubkey_x_C1 = NULL; 
	BIGNUM * pubkey_y_C1 = NULL; 
	BIGNUM *x2 = NULL;
	BIGNUM *y2 = NULL;
	BIGNUM * h = NULL;
	BIGNUM * privatekey = NULL;

	unsigned int x2Len = 0;
	unsigned int y2Len = 0;

	EC_POINT * C1 = NULL;
	EC_POINT * S = NULL;
	BN_CTX * ctx = NULL;
	unsigned char x2y2[2*GM_ECC_512_BYTES_LEN] = {0};

	gm_hash_context gm_hashCtx;


	int i = 0;

	if (!pbIN || uiINLen < (2*GM_ECC_512_BYTES_LEN+1+(GM_HASH_BYTES_LEN)) || !puiOUTLen
		|| !pbPrivateKey || uiPrivateKeyLen != GM_ECC_512_BYTES_LEN)
	{
		uiRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	uiPlainTextLen = uiINLen  -( 2*GM_ECC_512_BYTES_LEN + 1 + (GM_HASH_BYTES_LEN));

	if(!pbOUT)
	{
		*puiOUTLen = uiPlainTextLen;
		uiRet = 0;  // OK
		goto err;
	}
	if(*puiOUTLen < uiPlainTextLen)
	{
		*puiOUTLen = uiPlainTextLen;
		uiRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	if(!g_group512)
	{
		uiRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	ctx = BN_CTX_new();
	if (!ctx) 
	{
		uiRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	BN_CTX_start(ctx);

	C1 = EC_POINT_new(g_group512);
	S = EC_POINT_new(g_group512);

	if (!C1 || !S)
	{
		uiRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	privatekey = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);

	if( !privatekey || !h || !x2 || !y2)
	{
		uiRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	if (!EC_GROUP_get_cofactor(g_group512, h, ctx)) 
	{
		uiRet = -1;
		goto err;
	}

	t = (unsigned char *)OPENSSL_malloc(uiPlainTextLen);
	zero_buffer = (unsigned char *)OPENSSL_malloc(uiPlainTextLen);
	data_value_out = (unsigned char *)OPENSSL_malloc(uiPlainTextLen);

	memset(zero_buffer, 0, uiPlainTextLen);

	c1 = (unsigned char *)pbIN + 1;
	c2 = (unsigned char *)pbIN + GM_ECC_512_BYTES_LEN * 2 + 1;
	c3 = (unsigned char *)pbIN + GM_ECC_512_BYTES_LEN * 2 + 1 + uiPlainTextLen;

	// 第一步 
	// 从密文中取出C1
	pubkey_x_C1 = BN_bin2bn( c1,GM_ECC_512_BYTES_LEN, NULL );
	if (NULL == pubkey_x_C1)
	{
		uiRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	pubkey_y_C1 = BN_bin2bn( c1 + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN, NULL );
	if ( NULL == pubkey_y_C1)
	{
		uiRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	if (!EC_POINT_set_affine_coordinates_GFp(g_group512, C1, pubkey_x_C1, pubkey_y_C1, ctx) )
	{
		uiRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 
	// 判断C1是否满足曲线方程
	if(!EC_POINT_is_on_curve(g_group512, C1, ctx))
	{
		uiRet = -1;
		goto err;
	}

	// 第二步
	// 计算椭圆曲线点S=[h]C1
	if(!EC_POINT_mul(g_group512,S,NULL,C1,h,ctx))
	{
		uiRet = -1;
		goto err;
	}

	// S=O?
	if (EC_POINT_is_at_infinity(g_group512, S)) 
	{
		uiRet = -1;
		goto err;
	}

	// 第三步
	// 计算[db]C1=(x2,y2)=C2=S
	BN_bin2bn(pbPrivateKey, uiPrivateKeyLen ,privatekey);
	if(!EC_POINT_mul(g_group512,S,NULL,C1,privatekey,ctx))
	{
		uiRet = -1;
		goto err;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(g_group512, S, x2, y2, ctx))
	{
		uiRet = -1;
		goto err;
	}

	x2Len = BN_num_bytes(x2);
	y2Len = BN_num_bytes(y2);
	if( (x2Len>GM_ECC_512_BYTES_LEN) || (x2Len>GM_ECC_512_BYTES_LEN) )
	{
		uiRet = -1;
		goto err;
	}

	// 前补00
	x2Len = BN_bn2bin(x2, x2y2 + GM_ECC_512_BYTES_LEN - x2Len);
	y2Len = BN_bn2bin(y2, x2y2 + 2*GM_ECC_512_BYTES_LEN - y2Len);

	// 第四步
	// 计算t = KDF(x2||y2,klen)

	uiRet = gm_hash_kdf(t,uiPlainTextLen,x2y2,sizeof(x2y2),EHASH_TYPE_ZY_HASH_256);
	if(uiRet)
	{
		goto err;
	}

	// t全0
	if (0 == memcmp(zero_buffer,t,uiPlainTextLen))
	{
		uiRet = -1;
		goto err;
	}

	// 第五步
	// M'=C2^t
	for(i = 0; i < uiPlainTextLen; i++)
	{
		data_value_out[i] = t[i]^c2[i];
	}


	// 第六步
	// u = HASH(x2||M'||y2)
	memset(&gm_hashCtx,0x00,sizeof(gm_hashCtx));
	gm_hash_starts(&gm_hashCtx);
	gm_hash_update(&gm_hashCtx, x2y2, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, (unsigned char *)data_value_out, uiPlainTextLen);
	gm_hash_update(&gm_hashCtx, x2y2+GM_ECC_512_BYTES_LEN, GM_ECC_512_BYTES_LEN);
	gm_hash_finish(&gm_hashCtx, data_value_digest, EHASH_TYPE_ZY_HASH_256);

	if (0 == memcmp(c3,data_value_digest,(GM_HASH_BYTES_LEN)))
	{
		uiRet = 0;
		*puiOUTLen = uiPlainTextLen;
		memcpy(pbOUT,data_value_out,uiPlainTextLen);
	}
	else
	{
		uiRet = -1;
	}
err:
	if(t)
	{
		OPENSSL_free(t);
	}
	if(zero_buffer)
	{
		OPENSSL_free(zero_buffer);
	}
	if(data_value_out)
	{
		OPENSSL_free(data_value_out);
	}
	if (pubkey_x_C1)
	{
		BN_free(pubkey_x_C1);
	}
	if (pubkey_y_C1)
	{
		BN_free(pubkey_y_C1);
	}
	if (S)
	{
		EC_POINT_free(S);
	}
	if (C1)
	{
		EC_POINT_free(C1);
	}

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}

	return uiRet;
}



unsigned int OpenSSL_GMECC512EncryptInner(
	const unsigned char *pbIN, unsigned int uiINLen, 
	const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen, 
	const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen, 
	unsigned char *pbOUT, unsigned int * puiOUTLen
	)
{
	unsigned int uiRet = -1;
	unsigned int uiCiphertextLen = 0;
	BN_CTX * ctx = NULL;
	EC_POINT * pubkey_xy = NULL;
	EC_POINT * C1 = NULL;
	EC_POINT * S = NULL;

	unsigned char x2y2[GM_ECC_512_BYTES_LEN * 2] = {0};

	BIGNUM * pubkey_x = NULL;
	BIGNUM * pubkey_y = NULL;

	BIGNUM * order = NULL;
	BIGNUM * k = NULL;
	BIGNUM * h = NULL;
	BIGNUM *x2 = NULL;
	BIGNUM *y2 = NULL;

	unsigned int x2Len = 0;
	unsigned int y2Len = 0;

	unsigned char * t = NULL;
	unsigned char * zero_buffer = NULL;
	unsigned char * c1 = NULL; 
	unsigned char * c2 = NULL;
	unsigned char * c3 = NULL;
	int i = 0;

	gm_hash_context gm_hashCtx;

	// 判断是否初始化OPENSSL GROUP
	if(!g_group512)
	{
		uiRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	// 判断参数是否正确
	if(NULL == pbIN || 0 == uiINLen || NULL == pbPublicKeyX
		|| NULL == pbPublicKeyY || GM_ECC_512_BYTES_LEN != uiPublicKeyXLen || GM_ECC_512_BYTES_LEN != uiPublicKeyYLen
		|| NULL == puiOUTLen)
	{
		uiRet=OPE_ERR_INVALID_PARAM;
		goto err;
	}

	// 计算密文长度
	uiCiphertextLen =  2*GM_ECC_512_BYTES_LEN + 1 + uiINLen + (GM_HASH_BYTES_LEN);
	if(NULL == pbOUT)
	{
		*puiOUTLen = uiCiphertextLen;
		uiRet = 0;  // OK
		goto err;
	}
	if(*puiOUTLen < uiCiphertextLen)
	{
		*puiOUTLen  = uiCiphertextLen;
		uiRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	ctx = BN_CTX_new();
	if(!ctx)
	{
		uiRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	BN_CTX_start(ctx);

	pubkey_xy = EC_POINT_new(g_group512);
	C1 = EC_POINT_new(g_group512);
	S = EC_POINT_new(g_group512);

	if(!pubkey_xy || !C1 || !S)
	{
		uiRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	order = BN_CTX_get(ctx);
	k = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);

	if( !order || !k || !h || !x2 || !y2)
	{
		uiRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	if (!EC_GROUP_get_order(g_group512, order, ctx)) 
	{
		uiRet = -1;
		goto err;
	}

	if (!EC_GROUP_get_cofactor(g_group512, h, ctx)) 
	{
		uiRet = -1;
		goto err;
	}

	// 初始化公钥
	pubkey_x = BN_bin2bn( pbPublicKeyX,uiPublicKeyXLen, NULL );
	if (NULL == pubkey_x)
	{
		uiRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	pubkey_y = BN_bin2bn( pbPublicKeyY,uiPublicKeyYLen, NULL );
	if ( NULL == pubkey_y)
	{
		uiRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	if (!EC_POINT_set_affine_coordinates_GFp(g_group512, pubkey_xy, pubkey_x, pubkey_y, ctx) )
	{
		uiRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	t = (unsigned char *)OPENSSL_malloc(uiINLen);
	c1 = (unsigned char *)OPENSSL_malloc(2*GM_ECC_512_BYTES_LEN+1);
	c2 = (unsigned char *)OPENSSL_malloc(uiINLen);
	c3 = (unsigned char *)OPENSSL_malloc((GM_HASH_BYTES_LEN));
	zero_buffer = (unsigned char *)OPENSSL_malloc(uiINLen);

	if( !t || !c1 || !c2 || !c3 || !zero_buffer)
	{
		uiRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	memset(zero_buffer, 0, uiINLen);
	memset(c1, 0, 2*GM_ECC_512_BYTES_LEN+1);
	memset(c2, 0, uiINLen);
	memset(c3, 0, (GM_HASH_BYTES_LEN));

	for(;;)
	{

		// 第一步
		// 产生随机数
		for (;;)
		{
			if (!BN_rand_range(k, order)) 
			{
				uiRet = -1;
				goto err;
			}

			if (BN_is_zero(k))
			{
				continue;
			}
			else
			{
				break;
			}
		}
		// 第二步
		// C1=[k]G
		if (!EC_POINT_mul(g_group512, C1, k, NULL, NULL, ctx))
		{
			uiRet = -1;
			goto err;
		}

		if (!EC_POINT_get_affine_coordinates_GFp(g_group512, C1, pubkey_x, pubkey_y, ctx) )
		{
			uiRet = OPE_ERR_INVALID_PARAM;
			goto err;
		} 

		if(!EC_POINT_is_on_curve(g_group512, C1, ctx))
		{
			uiRet = -1;
			goto err;
		}

		c1[0]=0x04;
		BN_bn2bin(pubkey_x,c1+1);
		BN_bn2bin(pubkey_y,c1+1+GM_ECC_512_BYTES_LEN);

		// 第三步
		// S=[h]Pb
		if (!EC_POINT_mul(g_group512, S, NULL, pubkey_xy, h, ctx)) 
		{
			uiRet = -1;
			goto err;
		}
		// S=O
		if (EC_POINT_is_at_infinity(g_group512, S))
		{
			uiRet = -1;
			goto err;
		}
		// 第四步
		// S=[k]Pb=(x2,y2)
		if (!EC_POINT_mul(g_group512, S, NULL, pubkey_xy, k, ctx)) 
		{
			uiRet = -1;
			goto err;
		}
		// 获取x2y2
		if (!EC_POINT_get_affine_coordinates_GFp(g_group512, S, x2, y2, ctx)) 
		{
			uiRet = -1;
			goto err;
		}

		memset(x2y2, 0x00, sizeof(x2y2));

		x2Len = BN_num_bytes(x2);
		y2Len = BN_num_bytes(y2);
		if( (x2Len>GM_ECC_512_BYTES_LEN) || (x2Len>GM_ECC_512_BYTES_LEN) )
		{
			uiRet = -1;
			goto err;
		}

		// 前补00
		x2Len = BN_bn2bin(x2, x2y2 + GM_ECC_512_BYTES_LEN - x2Len);
		y2Len = BN_bn2bin(y2, x2y2 + 2*GM_ECC_512_BYTES_LEN - y2Len);

		// 第五步
		// t= KDF(x2||y2,klen)
		uiRet = gm_hash_kdf(t, uiINLen, x2y2, 2*GM_ECC_512_BYTES_LEN, EHASH_TYPE_ZY_HASH_256);

		// t全0
		if (0 == memcmp(zero_buffer,t,uiINLen))
		{
			continue;
		}else
		{
			break;
		}
	}

	// 第六步
	// C2=M^t
	for( i = 0; i< uiINLen; i++)
	{
		c2[i] = pbIN[i] ^ t[i];
	}
	// 第七步
	// C3=Hash(x2||M||y2)
	memset(&gm_hashCtx,0x00,sizeof(gm_hashCtx));
	gm_hash_starts(&gm_hashCtx);
	gm_hash_update(&gm_hashCtx, x2y2, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, (unsigned char *)pbIN, uiINLen);
	gm_hash_update(&gm_hashCtx, x2y2+GM_ECC_512_BYTES_LEN, GM_ECC_512_BYTES_LEN);
	gm_hash_finish(&gm_hashCtx, c3,EHASH_TYPE_ZY_HASH_256);

	uiRet = 0;

	memcpy(pbOUT,c1, GM_ECC_512_BYTES_LEN*2+1);
	memcpy(pbOUT + GM_ECC_512_BYTES_LEN*2+1 , c2, uiINLen);
	memcpy(pbOUT + GM_ECC_512_BYTES_LEN*2+1 + uiINLen,c3,(GM_HASH_BYTES_LEN));

	*puiOUTLen = GM_ECC_512_BYTES_LEN*2+1 + uiINLen + (GM_HASH_BYTES_LEN);

err:

	if(t)
	{
		OPENSSL_free(t);
	}
	if(c1)
	{
		OPENSSL_free(c1);
	}
	if(c2)
	{
		OPENSSL_free(c2);
	}
	if(c3)
	{
		OPENSSL_free(c3);
	}
	if(zero_buffer)
	{
		OPENSSL_free(zero_buffer);
	}
	if (pubkey_xy)
	{
		EC_POINT_free(pubkey_xy);
	}
	if (S)
	{
		EC_POINT_free(S);
	}
	if (C1)
	{
		EC_POINT_free(C1);
	}

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}

	return uiRet;
}


EVP_PKEY * OpenSSL_NewEVP_PKEY_OF_GMECC512Keys(
	const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
	const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen
	)
{
	EVP_PKEY	*pkey = NULL;
	EC_KEY		*ec = NULL;
	BN_CTX      *ctx=NULL;
	EC_POINT    *pubkey=NULL;
	BIGNUM      *pubkey_x=NULL, *pubkey_y=NULL, *prvkey=NULL;
	// 初始化证书公钥
	if((pkey = EVP_PKEY_new()) == NULL)
	{
		goto err;
	}
	if (!(ctx = BN_CTX_new()) )
	{
		goto err;
	}
	ec = EC_KEY_new();
	if (NULL==ec)
	{
		goto err;
	}
	if (!(EC_KEY_set_group(ec, g_group512)))
	{
		goto err;
	}
	if (!(pubkey = EC_POINT_new(g_group512)))
	{ 
		goto err;
	}
	if (!EC_KEY_generate_key(ec))
	{
		goto err;
	}

	/* set public key */
	pubkey_x = BN_bin2bn( pbPublicKeyX,uiPublicKeyXLen, NULL );
	if (NULL == pubkey_x)
	{
		goto err;
	} 

	pubkey_y = BN_bin2bn( pbPublicKeyY,uiPublicKeyYLen, NULL );
	if ( NULL == pubkey_y)
	{
		goto err;
	} 


	prvkey = BN_bin2bn( pbPrivateKey,uiPrivateKeyLen, NULL );
	if ( NULL == prvkey)
	{
		goto err;
	} 

	if ( !EC_POINT_set_affine_coordinates_GFp(g_group512, pubkey, pubkey_x, pubkey_y, ctx) )
	{
		goto err;
	} 


	if ( !EC_KEY_set_public_key(ec, pubkey) )
	{
		goto err;
	} 

	if ( !EC_KEY_set_private_key(ec,prvkey) )
	{
		goto err;
	}

	if(!EVP_PKEY_assign_EC_KEY(pkey, ec))
	{
		goto err;
	}

	ec = NULL;
err:
	if(ctx)
	{
		BN_CTX_free(ctx);
	}

	if(ec)
	{
		EC_KEY_free(ec);
	}

	return pkey;
}

unsigned int OpenSSL_GMECC512GenPFX(const char *password,const char *nickname, 
	const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
	const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
	const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
	const unsigned char * pbX509CA, unsigned int uiX509CALen,
	int nid_key, int nid_cert, int iter, int mac_iter, int keytype,
	unsigned char *pbPFX, unsigned int * puiPFXLen
	)
{
	X509 * x509 =  NULL;
	unsigned int rv = -1;
	PKCS12 * p12 = NULL;
	EVP_PKEY	*pkey = NULL;
	unsigned char *ptr_out = NULL;

	unsigned char value[BUFFER_LEN_1K * 4] = {0};
	unsigned int len = BUFFER_LEN_1K * 4;

	ptr_out = value;


	x509 = d2i_X509( NULL, (const unsigned char **)&pbX509Cert,uiX509CertLen);
	if (!x509)
	{	
		goto err;
	}

	pkey = OpenSSL_NewEVP_PKEY_OF_GMECC512Keys( 
		pbPrivateKey, uiPrivateKeyLen, 
		pbPublicKeyX, uiPublicKeyXLen, 
		pbPublicKeyY, uiPublicKeyYLen);

	if (!pkey)
	{
		goto err;
	}

	p12 = PKCS12_create(password, nickname, pkey, x509,
		NULL, nid_key, nid_cert, iter, mac_iter, keytype
		);


	//X509_ALGOR_set0(req->req_info->pubkey->algor,
	//	OBJ_txt2obj("1.2.840.10045.2.1",OBJ_NAME_TYPE_PKEY_METH)
	//	,V_ASN1_OBJECT,OBJ_txt2obj("1.2.156.10197.1.301",OBJ_NAME_TYPE_PKEY_METH)
	//	);

	//X509_ALGOR_set0(ec algor,
	//	OBJ_txt2obj("1.2.840.10045.2.1",OBJ_NAME_TYPE_PKEY_METH)
	//	,V_ASN1_OBJECT,OBJ_txt2obj("1.2.156.10197.1.301",OBJ_NAME_TYPE_PKEY_METH)
	//	);



	len = i2d_PKCS12(p12, NULL);

	if (len > *puiPFXLen)
	{
		*puiPFXLen = len;
	}
	else
	{
		len = i2d_PKCS12(p12, &ptr_out);
		*puiPFXLen = len;
		memcpy(pbPFX,value, len);
	}

	rv = 0;
err:

	if(x509)
	{
		X509_free(x509);
	}

	return rv;
}

#include "sm4.h"
#define	SGD_SMS4_ECB	0x00000401		//SMS4算法ECB加密模式

unsigned int OpenSSL_GMECC512GenExportEnvelopedKey(
	const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
	unsigned char *pbOUT, unsigned int * puiOUTLen
	)
{
	unsigned int rv = -1;

	unsigned char prv_data_value[GM_ECC_512_BYTES_LEN] = {0};
	unsigned char x_data_value[GM_ECC_512_BYTES_LEN] = {0};
	unsigned char y_data_value[GM_ECC_512_BYTES_LEN] = {0};
	unsigned int prv_data_len = GM_ECC_512_BYTES_LEN;
	unsigned int x_data_len = GM_ECC_512_BYTES_LEN;
	unsigned int y_data_len = GM_ECC_512_BYTES_LEN;

	unsigned char en_value[1+64*2+32+16] = {0};

	unsigned int en_len = 1+64*2+32+16;

	unsigned int sm4_key_len = 16;
	unsigned char sm4_key_value[16];

	OPST_SKF_ENVELOPEDKEYBLOB keyBlob = {0};

	sm4_context ctx;

	rv = OpenSSL_GMECC512GenKeys(x_data_value,&x_data_len,y_data_value,&y_data_len,prv_data_value,&prv_data_len);

	if(0 != rv)
	{
		goto err;
	}

	RAND_bytes(sm4_key_value,sm4_key_len);

	memset(&ctx,0,sizeof(sm4_context));

	sm4_setkey_enc(&ctx,sm4_key_value);


	keyBlob.Version = 1;
	keyBlob.uiBits = 512;
	keyBlob.uiSymmAlgID = SGD_SMS4_ECB;

	// 公钥赋值
	keyBlob.PubKey.BitLen = 512;
	memcpy(keyBlob.PubKey.XCoordinate,x_data_value,GM_ECC_512_BYTES_LEN);
	memcpy(keyBlob.PubKey.YCoordinate,y_data_value,GM_ECC_512_BYTES_LEN);

	rv = OpenSSL_GMECC512Encrypt(pbPublicKeyX,GM_ECC_512_BYTES_LEN,pbPublicKeyY,GM_ECC_512_BYTES_LEN,sm4_key_value,sm4_key_len,en_value,&en_len);
	if(0 != rv)
	{
		goto err;
	}

	keyBlob.ECCCipherBlob.CipherLen = 16;
	memcpy(keyBlob.ECCCipherBlob.HASH,en_value+1+64*2+16,32);
	memcpy(keyBlob.ECCCipherBlob.XCoordinate,en_value+1,GM_ECC_512_BYTES_LEN);
	memcpy(keyBlob.ECCCipherBlob.YCoordinate,en_value+1+64,GM_ECC_512_BYTES_LEN);
	memcpy(keyBlob.ECCCipherBlob.Cipher,en_value+1+64*2,16);

	sm4_crypt_ecb(&ctx,SM4_ENCRYPT,GM_ECC_512_BYTES_LEN,prv_data_value,keyBlob.cbEncryptedPriKey);

	if (pbOUT == NULL || *puiOUTLen == 0)
	{
		*puiOUTLen = sizeof(keyBlob);
	}
	else if (*puiOUTLen < sizeof(keyBlob))
	{
		rv = -1;
		goto err;
	}
	else
	{
		memcpy(pbOUT,&keyBlob,sizeof(keyBlob));

		*puiOUTLen = sizeof(keyBlob);
	}
	rv = 0;
err:

	return rv;
}

COMMON_API unsigned int OpenSSL_GMECC512RestoreExportEnvelopedKey(
	const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
	const unsigned char * pbOldPrivateKey, unsigned int uiOldPrivateKeyLen, 
	unsigned char *pbIN, unsigned int uiINLen,
	unsigned char *pbOUT, unsigned int * puiOUTLen
	)
{
	unsigned int rv = -1;

	unsigned char en_value[1+64*2+32+16] = {0};

	unsigned int en_len = 1+64*2+32+16;

	unsigned int sm4_key_len = 16;
	unsigned char sm4_key_value[16];

	OPST_SKF_ENVELOPEDKEYBLOB keyBlob;

	// set in and out;
	memcpy(&keyBlob,pbIN,sizeof(OPST_SKF_ENVELOPEDKEYBLOB));

	//
	en_value[0] = 0x04;

	memcpy(en_value+1+64*2+16,keyBlob.ECCCipherBlob.HASH,32);
	memcpy(en_value+1,keyBlob.ECCCipherBlob.XCoordinate,GM_ECC_512_BYTES_LEN);
	memcpy(en_value+1+64,keyBlob.ECCCipherBlob.YCoordinate,GM_ECC_512_BYTES_LEN);
	memcpy(en_value+1+64*2,keyBlob.ECCCipherBlob.Cipher,16);

	rv = OpenSSL_GMECC512Decrypt(pbOldPrivateKey,GM_ECC_512_BYTES_LEN,en_value,en_len,sm4_key_value,&sm4_key_len);
	if(0 != rv)
	{
		goto err;
	}

	rv = OpenSSL_GMECC512Encrypt(pbPublicKeyX,GM_ECC_512_BYTES_LEN,pbPublicKeyY,GM_ECC_512_BYTES_LEN,sm4_key_value,sm4_key_len,en_value,&en_len);
	if(0 != rv)
	{
		goto err;
	}

	keyBlob.ECCCipherBlob.CipherLen = 16;
	memcpy(keyBlob.ECCCipherBlob.HASH,en_value+1+64*2+16,32);
	memcpy(keyBlob.ECCCipherBlob.XCoordinate,en_value+1,GM_ECC_512_BYTES_LEN);
	memcpy(keyBlob.ECCCipherBlob.YCoordinate,en_value+1+64,GM_ECC_512_BYTES_LEN);
	memcpy(keyBlob.ECCCipherBlob.Cipher,en_value+1+64*2,16);

	if (pbOUT == NULL || *puiOUTLen == 0)
	{
		*puiOUTLen = sizeof(keyBlob);
	}
	else if (*puiOUTLen < sizeof(keyBlob))
	{
		rv = -1;
		goto err;
	}
	else
	{
		memcpy(pbOUT,&keyBlob,sizeof(keyBlob));

		*puiOUTLen = sizeof(keyBlob);
	}
	rv = 0;
err:

	return rv;
}


#if defined(GM_ECC_512_SUPPORT_SKF)

#include "KMS_CAPI.h"

unsigned int SKF_GMECC512SignCRL(
	const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
	const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
	const char * pbPIN,unsigned int ulKeyTarget, unsigned int *pulRetry,
	unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
	)
{
	unsigned int rv = -1;
	X509_CRL * crl =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int uiSigLen = BUFFER_LEN_1K;
	//EC_KEY      * ecPubkey = NULL;

	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;

	unsigned int r_len = GM_ECC_512_BYTES_LEN;
	unsigned int s_len = GM_ECC_512_BYTES_LEN;

	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	char pszKeyOn[BUFFER_LEN_1K];


	ptr_in = pbCRL;
	crl = d2i_X509_CRL(NULL, &ptr_in, uiCRLLen);
	if (NULL == crl)
	{
		goto err;
	}

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	GMECC512SignAsn1DeConvert(pbSig,&r_len,pbSig+ GM_ECC_512_BYTES_LEN,&s_len,crl->signature->data,crl->signature->length);

	//rv = OpenSSL_VerifyMSG(cert_buffer_data,cert_buffer_len, sig,2 * GM_ECC_512_BYTES_LEN,pbPublicKeyX,GM_ECC_512_BYTES_LEN,pbPublicKeyY,GM_ECC_512_BYTES_LEN);

	info_len =i2d_X509_CRL_INFO(crl->crl,&ptr_out);

	//ASN1_item_i2d(cer->cert_info,&pCert,ASN1_ITEM_rptr(X509_CINF));

	rv = tcm_gmecc512_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if(rv)
	{
		goto err;
	}

	rv = CAPI_KEY_ECC512SignDigest(pszKeyOn,ulKeyTarget,pbPIN, digest_value, pbSig,pulRetry);
	if(rv)
	{
		goto err;
	}
	rv = GMECC512SignAsn1Convert(pbSig,GM_ECC_512_BYTES_LEN, pbSig + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN, encode_value, &encode_len);
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

	ptr_out = pbCRLSigned;
	*puiCRLSignedLen =  i2d_X509_CRL(crl, &ptr_out);

	rv = 0;

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, rv);

err:

	if (crl)
	{
		X509_CRL_free(crl);
	}

	return rv;
}


unsigned int SKF_GMECC512SignCert(
	const unsigned char *pbX509Cert,   unsigned int uiX509CertLen, 
	const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
	const char * pbPIN,unsigned int ulKeyTarget, unsigned int *pulRetry,
	unsigned char * pbX509CertSigned,  unsigned int *puiX509CertSignedLen
	)
{
	unsigned int rv = -1;
	X509 * x509 =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int uiSigLen = BUFFER_LEN_1K;

	unsigned char digest_value[GM_HASH_MAX_BYTES_LEN] = {0};
	unsigned int digest_len = GM_HASH_MAX_BYTES_LEN;

	unsigned int r_len = GM_ECC_512_BYTES_LEN;
	unsigned int s_len = GM_ECC_512_BYTES_LEN;

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	char pszKeyOn[BUFFER_LEN_1K];

	ptr_in = pbX509Cert;
	x509 = d2i_X509(NULL, &ptr_in, uiX509CertLen);
	if (NULL == x509)
	{
		goto err;
	}

	ptr_out = info_value;

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, GM_ECC_512_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + GM_ECC_512_BYTES_LEN, pbPublicKeyY, GM_ECC_512_BYTES_LEN);

	info_len =i2d_X509_CINF(x509->cert_info,&ptr_out);

	rv = tcm_gmecc512_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);

	if (rv)
	{
		goto err;
	}

	rv = CAPI_KEY_ECC512SignDigest(pszKeyOn,ulKeyTarget,pbPIN, digest_value, pbSig,pulRetry);
	if (rv)
	{
		goto err;
	}

	rv = GMECC512SignAsn1Convert(pbSig,GM_ECC_512_BYTES_LEN, pbSig + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN, encode_value, &encode_len);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"encode_value");
	FILE_LOG_HEX(file_log_name, encode_value, encode_len);
	if (rv)
	{
		goto err;
	}

	ASN1_BIT_STRING_set(x509->signature,encode_value, encode_len);
	x509->signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	x509->signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;

	ptr_out = pbX509CertSigned;
	*puiX509CertSignedLen =  i2d_X509(x509, &ptr_out);

	rv = 0;

err:

	if (x509)
	{
		X509_free(x509);
	}

	return rv;
}

#endif