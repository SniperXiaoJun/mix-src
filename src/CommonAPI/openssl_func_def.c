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

#include "sm2.h"
#include "sm3.h"

#include "string.h"
#include "openssl/x509v3.h"

#if defined(GM_ECC_512_SUPPORT)
#include "gm-ecc-512.h"
#endif 


extern EC_GROUP *g_group;


int copy_extensions(X509 *x, X509_REQ *req, int copy_type);
short Add_Ext(X509 *cert, X509 * root, int nid, char *value);

unsigned int OpenSSL_AddNameByID(X509_NAME * aX509Name,  unsigned int aType, unsigned char * aDataValue, unsigned int aDataLen, unsigned int aDataType);//��Ӣ�Ĵ���
unsigned int OpenSSL_AddNameByName(X509_NAME * aX509Name, const char * aType, unsigned char * aDataValue, unsigned int aDataLen, unsigned int aDataType);//��Ӣ�Ĵ���


EVP_PKEY * OpenSSL_NewEVP_PKEY_OF_SM2_PublicKey(
	const unsigned char * pbPublicKeyX, unsigned int ulPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int ulPublicKeyYLen
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
	if (!(EC_KEY_set_group(ec, g_group)))
	{
		goto err;
	}
	if (!(pubkey = EC_POINT_new(g_group)))
	{ 
		goto err;
	}
	if (!EC_KEY_generate_key(ec))
	{
		goto err;
	}

	/* set public key */
	pubkey_x = BN_bin2bn( pbPublicKeyX,ulPublicKeyXLen, NULL );
	if (NULL == pubkey_x)
	{
		goto err;
	} 

	pubkey_y = BN_bin2bn( pbPublicKeyY,ulPublicKeyYLen, NULL );
	if ( NULL == pubkey_y)
	{
		goto err;
	} 

	if ( !EC_POINT_set_affine_coordinates_GFp(g_group, pubkey, pubkey_x, pubkey_y, ctx) )
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





typedef struct SM2SIGN_DATA_st
{	
	ASN1_INTEGER	*r;
	ASN1_INTEGER	*s;
}SM2SIGN_DATA;

DECLARE_ASN1_FUNCTIONS(SM2SIGN_DATA)
ASN1_SEQUENCE(SM2SIGN_DATA) ={		
	ASN1_SIMPLE(SM2SIGN_DATA, r, ASN1_INTEGER),
	ASN1_SIMPLE(SM2SIGN_DATA, s, ASN1_INTEGER)
}

ASN1_SEQUENCE_END(SM2SIGN_DATA)
	IMPLEMENT_ASN1_FUNCTIONS(SM2SIGN_DATA)


	unsigned int SM2SignAsn1Convert(
	unsigned char *pbR, unsigned int nRLen,
	unsigned char *pbS, unsigned int nSLen,
	unsigned char *pbOutDer, unsigned int *pOutDerLen) 
{	
	unsigned long			nOutLen = 0;
	unsigned long			nRet = 0;

	unsigned char *p = NULL;
	unsigned char pbOut[2048] = {0};
	unsigned char *pOut = pbOut;

	SM2SIGN_DATA  stData;

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
	nOutLen = i2d_SM2SIGN_DATA(&stData, &pOut);

	*pOutDerLen = nOutLen;

	if(pbOutDer)
		memcpy(pbOutDer, pbOut, nOutLen);

ErrExit:	

	return nRet;
}

unsigned int SM2SignAsn1DeConvert(
	unsigned char *pbR, unsigned int *nRLen,
	unsigned char *pbS, unsigned int *nSLen,
	unsigned char *pbDer, unsigned int nDerLen) 
{	
	unsigned int 		nOutLen = 0;
	unsigned long		nRet = 0;

	unsigned char * pPtr = pbDer;

	SM2SIGN_DATA  * stData = d2i_SM2SIGN_DATA(NULL, &pPtr,nDerLen);

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

unsigned int OpenSSL_Initialize()
{
	// OpenSSL ���ʼ��
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();

	// ��ʼ��SM2����
	tcm_ecc_init();

#if defined(GM_ECC_512_SUPPORT)
	tcm_gmecc512_init();
#endif 

	return 0;
}

unsigned int OpenSSL_Finalize()
{

#if defined(GM_ECC_512_SUPPORT)
	tcm_gmecc512_release();
#endif 

	return tcm_ecc_release();
}

unsigned int OpenSSL_SM2GenKeys(unsigned char * pbPublicKeyX,  unsigned int * puiPublicKeyXLen, 
	unsigned char * pbPublicKeyY,  unsigned int * puiPublicKeyYLen,
	unsigned char * pbPrivateKey,  unsigned int * puiPrivateKeyLen)
{
	EC_KEY		*ec = NULL;
	unsigned long		rv	= -1;

	BN_CTX *ctx=NULL;
	EC_POINT *pubkey=NULL;
	BIGNUM *pubkey_x=NULL, *pubkey_y=NULL,*prvkey=NULL;

	unsigned char data_value_x[SM2_BYTES_LEN]= {0};
	unsigned char data_value_y[SM2_BYTES_LEN]= {0};
	unsigned char data_value_prv[SM2_BYTES_LEN]= {0};
	unsigned int data_len_x = SM2_BYTES_LEN;
	unsigned int data_len_y = SM2_BYTES_LEN;
	unsigned int data_len_prv = SM2_BYTES_LEN;

	// ������Կ��
	if ( !(ctx = BN_CTX_new()) )
	{
		goto err;
	}

	ec = EC_KEY_new();
	if (NULL==ec)
	{
		goto err;
	}

	if ( !(EC_KEY_set_group(ec, g_group)) )
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

	EC_POINT_get_affine_coordinates_GFp(g_group,pubkey,pubkey_x,pubkey_y,ctx);
	data_len_x = BN_bn2bin(pubkey_x, data_value_x);
	data_len_y = BN_bn2bin(pubkey_y,data_value_y);
	data_len_prv = BN_bn2bin(prvkey,data_value_prv);

	if(* puiPublicKeyYLen < SM2_BYTES_LEN || * puiPublicKeyXLen <SM2_BYTES_LEN || *puiPrivateKeyLen < SM2_BYTES_LEN)
	{
		rv = -1;
		goto err;
	}
	else
	{
		*puiPublicKeyYLen = SM2_BYTES_LEN;
		*puiPublicKeyXLen = SM2_BYTES_LEN;
		*puiPrivateKeyLen = SM2_BYTES_LEN;

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

unsigned int OpenSSL_SM2VerifyCert(const unsigned char *pbX509Cert, unsigned int ulX509CertLen,unsigned int ulAlg,
	const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen)
{
	unsigned int rv = -1;
	X509 * x509 =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int ulSigLen = BUFFER_LEN_1K;

	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;

	unsigned int r_len = SM3_DIGEST_LEN;
	unsigned int s_len = SM3_DIGEST_LEN;

	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	ptr_in = pbX509Cert;
	x509 = d2i_X509(NULL, &ptr_in, ulX509CertLen);
	if (NULL == x509)
	{
		goto err;
	}
	

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, SM2_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + SM2_BYTES_LEN, pbPublicKeyY, SM2_BYTES_LEN);

	rv = SM2SignAsn1DeConvert(pbSig,&r_len,pbSig+ SM2_BYTES_LEN,&s_len,x509->signature->data,x509->signature->length);
	if(rv)
	{
		goto err;
	}

	//rv = OpenSSL_VerifyMSG(cert_buffer_data,cert_buffer_len, sig,2 * SM2_BYTES_LEN,pbPublicKeyX,SM2_BYTES_LEN,pbPublicKeyY,SM2_BYTES_LEN);

	info_len =i2d_X509_CINF(x509->cert_info,&ptr_out);

	//ASN1_item_i2d(cer->cert_info,&pCert,ASN1_ITEM_rptr(X509_CINF));

	rv = tcm_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if(rv)
	{
		goto err;
	}

	rv = OpenSSL_SM2VerifyDigest(digest_value,digest_len, pbSig,2 * SM2_BYTES_LEN,pbPublicKeyX,SM2_BYTES_LEN,pbPublicKeyY,SM2_BYTES_LEN);
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


unsigned int OpenSSL_SM2VerifyCRL(const unsigned char *pbCRL, unsigned int ulCRLLen,unsigned int ulAlg,
	const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen)
{
	unsigned int rv = -1;
	X509_CRL * crl =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int ulSigLen = BUFFER_LEN_1K;
	EC_KEY      * ecPubkey = NULL;

	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;

	unsigned int r_len = SM3_DIGEST_LEN;
	unsigned int s_len = SM3_DIGEST_LEN;

	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	ptr_in = pbCRL;
	crl = d2i_X509_CRL(NULL, &ptr_in, ulCRLLen);
	if (NULL == crl)
	{
		goto err;
	}

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, SM2_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + SM2_BYTES_LEN, pbPublicKeyY, SM2_BYTES_LEN);

	SM2SignAsn1DeConvert(pbSig,&r_len,pbSig+ SM2_BYTES_LEN,&s_len,crl->signature->data,crl->signature->length);

	//rv = OpenSSL_VerifyMSG(cert_buffer_data,cert_buffer_len, sig,2 * SM2_BYTES_LEN,pbPublicKeyX,SM2_BYTES_LEN,pbPublicKeyY,SM2_BYTES_LEN);

	info_len =i2d_X509_CRL_INFO(crl->crl,&ptr_out);

	//ASN1_item_i2d(cer->cert_info,&pCert,ASN1_ITEM_rptr(X509_CINF));

	rv = tcm_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if(rv)
	{
		goto err;
	}

	rv = OpenSSL_SM2VerifyDigest(digest_value,digest_len, pbSig,2 * SM2_BYTES_LEN,pbPublicKeyX,SM2_BYTES_LEN,pbPublicKeyY,SM2_BYTES_LEN);
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

unsigned int OpenSSL_SM2VerifyMSG(const unsigned char *pbMSG, unsigned int ulMSGLen, 
	const unsigned char *pbSig, unsigned int ulSigLen,
	const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen)
{
	unsigned int rv	= -1;
	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;

	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, SM2_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + SM2_BYTES_LEN, pbPublicKeyY, SM2_BYTES_LEN);

	rv = tcm_get_message_hash((unsigned char *)pbMSG, ulMSGLen,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);

	if (rv)
	{
		goto err;
	}


	rv = OpenSSL_SM2VerifyDigest(digest_value,digest_len,pbSig,ulSigLen,pbPublicKeyX,ulPublicKeyXLen,pbPublicKeyY,ulPublicKeyYLen);
	if (rv)
	{
		goto err;
	}

err:

	return rv;
}

unsigned int OpenSSL_SM2VerifyCSR(
	const unsigned char *pbCSR, unsigned int ulCSRLen,
	unsigned int ulAlg
	)
{
	EVP_PKEY	*pktmp = NULL;			// req�еĹ�Կ
	X509_REQ *req = NULL;
	unsigned int rv = -1;
	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;
	unsigned char pbPublicKeyX[SM2_BYTES_LEN] = {0};
	unsigned char pbPublicKeyY[SM2_BYTES_LEN] = {0};
	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;

	unsigned int r_len = SM3_DIGEST_LEN;
	unsigned int s_len = SM3_DIGEST_LEN;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int ulSigLen = BUFFER_LEN_1K;

	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;

	ptr_in = pbCSR;

	req = d2i_X509_REQ(NULL, &ptr_in, ulCSRLen);
	if (NULL == req)
	{
		goto err;
	}
	
	// �õ�req�еĹ�Կ
	if((pktmp=X509_REQ_get_pubkey(req)) == NULL)
	{
		//goto err;
		pktmp = OpenSSL_NewEVP_PKEY_OF_SM2_PublicKey(
			req->req_info->pubkey->public_key->data + 1,
			SM2_BYTES_LEN,
			req->req_info->pubkey->public_key->data + 1 + SM2_BYTES_LEN,
			SM2_BYTES_LEN
			);
	}

	if (pktmp == NULL)
	{
		goto err;
	}

	ptr_out = info_value;

	info_len = i2d_X509_REQ_INFO(req->req_info, &ptr_out);

	memcpy(pubkey_xy_value, req->req_info->pubkey->public_key->data, req->req_info->pubkey->public_key->length);
	memcpy(pbPublicKeyX, pubkey_xy_value + 1, SM2_BYTES_LEN);
	memcpy(pbPublicKeyY, pubkey_xy_value + 1 + SM2_BYTES_LEN, SM2_BYTES_LEN);

	if (req->signature->length != 2 * SM2_BYTES_LEN)
	{
		SM2SignAsn1DeConvert(pbSig,&r_len,pbSig+ SM2_BYTES_LEN,&s_len,req->signature->data,req->signature->length);
		rv = tcm_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	}
	else
	{
		memcpy(pbSig,req->signature->data,req->signature->length);
		rv = tcm_sch_hash(info_len, info_value,digest_value);
	}

	if(rv)
	{
		goto err;
	}
	
	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_STRING(file_log_name, "OpenSSL..........OpenSSL_SM2VerifyCSR");

	FILE_LOG_STRING(file_log_name, "tcm_get_message_hash pbPublicKey");
	FILE_LOG_HEX(file_log_name,pubkey_xy_value, SM2_BYTES_LEN * 2 + 1);

	FILE_LOG_STRING(file_log_name, "tcm_get_message_hash pbDigest");
	FILE_LOG_HEX(file_log_name,digest_value, digest_len);

	FILE_LOG_STRING(file_log_name, "tcm_get_message_hash m_szCsr");
	FILE_LOG_HEX(file_log_name,info_value, info_len);


	rv = OpenSSL_SM2VerifyDigest(digest_value,SM2_BYTES_LEN,pbSig,2 * SM2_BYTES_LEN,pbPublicKeyX, SM2_BYTES_LEN, pbPublicKeyY, SM2_BYTES_LEN);
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


unsigned int OpenSSL_GetX509Content(
	const unsigned char *pbX509, unsigned int ulX509Len,
	X509_TYPE ulX509Type,/*0,1,2分别代表CSR,CERT,CRL*/
	unsigned char *pbX509Content, unsigned int *puiX509ContentLen
	)
{
	X509_REQ *req = NULL;
	X509 *x509 = NULL;
	X509_CRL *crl = NULL;
	unsigned int rv = -1;
	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;

	ptr_in = pbX509;
	ptr_out = pbX509Content;

	switch(ulX509Type)
	{
	case X509_TYPE_CSR:
		{
			req = d2i_X509_REQ(NULL, &ptr_in, ulX509Len);
			if (NULL == req)
			{
				goto err;
			}
			*puiX509ContentLen = i2d_X509_REQ_INFO(req->req_info, &ptr_out);
		}
		break;
	case X509_TYPE_CERT:
		{
			x509 = d2i_X509(NULL, &ptr_in, ulX509Len);
			if (NULL == req)
			{
				goto err;
			}

			*puiX509ContentLen =i2d_X509_CINF(x509->cert_info,&ptr_out);
		}
		break;
	case X509_TYPE_CRL:
		{
			crl = d2i_X509_CRL(NULL, &ptr_in, ulX509Len);
			if (NULL == req)
			{
				goto err;
			}
			*puiX509ContentLen =i2d_X509_CRL_INFO(crl->crl,&ptr_out);
		}
		break;
	default:
		goto err;
		break;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"");
	FILE_LOG_HEX(file_log_name, ptr_in, ulX509Len);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"");
	FILE_LOG_HEX(file_log_name, ptr_out, *puiX509ContentLen);

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



unsigned int OpenSSL_SM2SignCSR(
	const unsigned char *pbCSR, unsigned int ulCSRLen,
	const unsigned char * pbPrivateKey,unsigned int ulPrivateKeyLen,
	unsigned int ulAlg,
	unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen
	)
{
	EVP_PKEY	*pktmp = NULL;			// req�еĹ�Կ
	X509_REQ *req = NULL;
	BN_CTX *ctx=NULL;
	EC_KEY      * ecPubkey = NULL;
	const EC_POINT	* pubkey = NULL;
	BIGNUM * pubkey_x = NULL;
	BIGNUM * pubkey_y = NULL;
	unsigned int rv = -1;
	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;
	unsigned char pbPublicKeyX[SM2_BYTES_LEN] = {0};
	unsigned char pbPublicKeyY[SM2_BYTES_LEN] = {0};
	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	unsigned int r_len = SM3_DIGEST_LEN;
	unsigned int s_len = SM3_DIGEST_LEN;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int ulSigLen = BUFFER_LEN_1K;

	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;

	ptr_in = pbCSR;

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_HEX(file_log_name, ptr_in, ulCSRLen);

	req = d2i_X509_REQ(NULL, &ptr_in, ulCSRLen);
	if (NULL == req)
	{
		goto err;
	}

	if ( !(ctx = BN_CTX_new()) )
	{		
		goto err;	
	}

	// �õ�req�еĹ�Կ
	if((pktmp=X509_REQ_get_pubkey(req)) == NULL)
	{
		//goto err;
		pktmp = OpenSSL_NewEVP_PKEY_OF_SM2_PublicKey(
			req->req_info->pubkey->public_key->data + 1,
			SM2_BYTES_LEN,
			req->req_info->pubkey->public_key->data + 1 + SM2_BYTES_LEN,
			SM2_BYTES_LEN
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
	


	EC_POINT_get_affine_coordinates_GFp(g_group,pubkey,pubkey_x,pubkey_y,ctx);

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_num_bytes(pubkey_x));
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_num_bytes(pubkey_y));
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, pubkey_x);
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, pubkey_y);
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_bn2bin(pubkey_x, pbPublicKeyX));
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, BN_bn2bin(pubkey_y, pbPublicKeyY));


	BN_bn2bin(pubkey_x, pbPublicKeyX);
	BN_bn2bin(pubkey_y, pbPublicKeyY);

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, SM2_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + SM2_BYTES_LEN, pbPublicKeyY, SM2_BYTES_LEN);

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);
	FILE_LOG_HEX(file_log_name, pubkey_xy_value,65);

	memcpy(pubkey_xy_value, req->req_info->pubkey->public_key->data, req->req_info->pubkey->public_key->length);
	
	FILE_LOG_HEX(file_log_name, pubkey_xy_value,65);

	rv = tcm_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if(rv)
	{
		goto err;
	}

	rv = OpenSSL_SM2SignDigest(digest_value, digest_len, pbPrivateKey,ulPrivateKeyLen, pbSig,&ulSigLen);
	if(rv)
	{
		goto err;
	}
	FILE_LOG_HEX(file_log_name, pbSig,ulSigLen);
	
	FILE_LOG_HEX(file_log_name, digest_value,digest_len);
	FILE_LOG_HEX(file_log_name, pubkey_xy_value,65);
	rv = SM2SignAsn1Convert(pbSig,SM2_BYTES_LEN, pbSig + SM2_BYTES_LEN,SM2_BYTES_LEN, encode_value, &encode_len);
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


unsigned int OpenSSL_SM2SetX509SignValue(
	const unsigned char *pbX509, unsigned int ulX509Len,
	X509_TYPE ulX509Type,
	const unsigned char *pbR, unsigned int ulRLen,
	const unsigned char *pbS, unsigned int ulSLen,
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

	rv = SM2SignAsn1Convert(pbR,SM2_BYTES_LEN, pbS,SM2_BYTES_LEN, encode_value, &encode_len);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"encode_value");
	FILE_LOG_HEX(file_log_name, encode_value, encode_len);
	if (rv)
	{
		goto err;
	}

	switch(ulX509Type)
	{
	case X509_TYPE_CSR:
		{
			req = d2i_X509_REQ(NULL, &ptr_in, ulX509Len);
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
			x509 = d2i_X509(NULL, &ptr_in, ulX509Len);
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
			crl = d2i_X509_CRL(NULL, &ptr_in, ulX509Len);
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
	default:
		goto err;
		break;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"ptr_in");
	FILE_LOG_HEX(file_log_name, ptr_in, ulX509Len);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"ptr_out");
	FILE_LOG_HEX(file_log_name, ptr_out, *puiX509SignedLen);

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


unsigned int OpenSSL_SM2SignMSG(const unsigned char *pbMSG, unsigned int ulMSGLen, 
	const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen,
	const unsigned char * pbPrivateKey,unsigned int ulPrivateKeyLen,
	unsigned int ulAlg,
	unsigned char *pbSig, unsigned int * puiSigLen)
{
	unsigned int rv	= -1;
	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;

	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, SM2_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + SM2_BYTES_LEN, pbPublicKeyY, SM2_BYTES_LEN);

	rv = tcm_get_message_hash((unsigned char *)pbMSG, ulMSGLen,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if (rv)
	{
		goto err;
	}

	rv = OpenSSL_SM2SignDigest(digest_value, digest_len, pbPrivateKey,ulPrivateKeyLen, pbSig,puiSigLen);
	if(rv)
	{
		goto err;
	}

err:

	return rv;
}

unsigned int OpenSSL_SM2SignCRL(
	const unsigned char *pbCRL, unsigned int ulCRLLen,unsigned int ulAlg,
	const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen,
	const unsigned char * pbPrivateKey,unsigned int ulPrivateKeyLen,
	unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
	)
{
	unsigned int rv = -1;
	X509_CRL * crl =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int ulSigLen = BUFFER_LEN_1K;
	//EC_KEY      * ecPubkey = NULL;

	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;

	unsigned int r_len = SM3_DIGEST_LEN;
	unsigned int s_len = SM3_DIGEST_LEN;

	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	ptr_in = pbCRL;
	crl = d2i_X509_CRL(NULL, &ptr_in, ulCRLLen);
	if (NULL == crl)
	{
		goto err;
	}
	
	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, SM2_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + SM2_BYTES_LEN, pbPublicKeyY, SM2_BYTES_LEN);

	SM2SignAsn1DeConvert(pbSig,&r_len,pbSig+ SM2_BYTES_LEN,&s_len,crl->signature->data,crl->signature->length);

	//rv = OpenSSL_VerifyMSG(cert_buffer_data,cert_buffer_len, sig,2 * SM2_BYTES_LEN,pbPublicKeyX,SM2_BYTES_LEN,pbPublicKeyY,SM2_BYTES_LEN);

	info_len =i2d_X509_CRL_INFO(crl->crl,&ptr_out);

	//ASN1_item_i2d(cer->cert_info,&pCert,ASN1_ITEM_rptr(X509_CINF));

	rv = tcm_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);
	if(rv)
	{
		goto err;
	}

	rv = OpenSSL_SM2SignDigest(digest_value, digest_len, pbPrivateKey,ulPrivateKeyLen, pbSig,&ulSigLen);
	if(rv)
	{
		goto err;
	}
	rv = SM2SignAsn1Convert(pbSig,SM2_BYTES_LEN, pbSig + SM2_BYTES_LEN,SM2_BYTES_LEN, encode_value, &encode_len);
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


unsigned int OpenSSL_SM2SignCert(
	const unsigned char *pbX509Cert,   unsigned int ulX509CertLen, 
	const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
	const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen,
	const unsigned char *pbPrivateKey, unsigned int ulPrivateKeyLen,
	unsigned char * pbX509CertSigned,  unsigned int *puiX509CertSignedLen
	)
{
	unsigned int rv = -1;
	X509 * x509 =  NULL;
	unsigned char pbSig[BUFFER_LEN_1K] = {0};
	unsigned int ulSigLen = BUFFER_LEN_1K;

	unsigned char digest_value[SM3_DIGEST_LEN] = {0};
	unsigned int digest_len = SM3_DIGEST_LEN;

	unsigned int r_len = SM3_DIGEST_LEN;
	unsigned int s_len = SM3_DIGEST_LEN;

	unsigned int encode_len = BUFFER_LEN_1K;
	unsigned char encode_value[BUFFER_LEN_1K] = {0};

	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	unsigned char info_value[BUFFER_LEN_1K * 4] = {0};
	unsigned int info_len = BUFFER_LEN_1K * 4;
	unsigned char *ptr_out = info_value;
	const unsigned char * ptr_in = NULL;

	ptr_in = pbX509Cert;
	x509 = d2i_X509(NULL, &ptr_in, ulX509CertLen);
	if (NULL == x509)
	{
		goto err;
	}
	
	ptr_out = info_value;

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, SM2_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + SM2_BYTES_LEN, pbPublicKeyY, SM2_BYTES_LEN);

	info_len =i2d_X509_CINF(x509->cert_info,&ptr_out);

	rv = tcm_get_message_hash(info_value, info_len,"1234567812345678", 16, pubkey_xy_value, pubkey_xy_len,digest_value,&digest_len);

	if (rv)
	{
		goto err;
	}

	rv = OpenSSL_SM2SignDigest(digest_value, digest_len, pbPrivateKey,ulPrivateKeyLen, pbSig,&ulSigLen);
	if (rv)
	{
		goto err;
	}

	rv = SM2SignAsn1Convert(pbSig,SM2_BYTES_LEN, pbSig + SM2_BYTES_LEN,SM2_BYTES_LEN, encode_value, &encode_len);
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

unsigned int OpenSSL_SM2GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
	const unsigned char * pbPublicKeyX,  unsigned int ulPublicKeyXLen, 
	const unsigned char * pbPublicKeyY,  unsigned int ulPublicKeyYLen,
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

	pkey = OpenSSL_NewEVP_PKEY_OF_SM2_PublicKey(
		pbPublicKeyX,
		SM2_BYTES_LEN,
		pbPublicKeyY,
		SM2_BYTES_LEN
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

	// they 4 are all ok and must be CN, others not invalid
	//X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,"CN", -1, -1, 0);
	//X509_NAME_add_entry_by_NID(name,NID_countryName, MBSTRING_ASC,"CN", -1,-1,0);
	//X509_NAME_add_entry_by_NID(name,NID_countryName, MBSTRING_UTF8,"CN", -1,-1,0);
	//X509_NAME_add_entry_by_NID(name,NID_countryName, MBSTRING_UTF8,"CN", 2,-1,0);

	OpenSSL_AddNameByName(name, "C", (unsigned char *)pstUserInfo->countryName,pstUserInfo->ulLenC,0);
	OpenSSL_AddNameByName(name, "ST", (unsigned char *)pstUserInfo->stateOrProvinceName,pstUserInfo->ulLenST,0);
	OpenSSL_AddNameByName(name, "L", (unsigned char *)pstUserInfo->localityName,pstUserInfo->ulLenL, 0);
	OpenSSL_AddNameByName(name, "O", (unsigned char *)pstUserInfo->organizationName,pstUserInfo->ulLenO, 0);
	OpenSSL_AddNameByName(name, "OU",(unsigned char *) pstUserInfo->organizationalUnitName,pstUserInfo->ulLenOU,0);
	OpenSSL_AddNameByName(name, "CN",(unsigned char *) pstUserInfo->commonName,pstUserInfo->ulLenCN,0);
	OpenSSL_AddNameByName(name, "emailAddress",(unsigned char *) pstUserInfo->emailAddress,pstUserInfo->ulLenEA,0);
	OpenSSL_AddNameByName(name, "challengePassword",(unsigned char *)pstUserInfo->challengePassword, pstUserInfo->ulLenCP, 0);
	OpenSSL_AddNameByName(name, "unstructuredName",(unsigned char *)pstUserInfo->unstructuredName,pstUserInfo->ulLenUN,0);
	

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

unsigned int OpenSSL_SM2GenRootCert(const unsigned char * pbCSR,unsigned int ulCSRLen,
	unsigned char * pbSerialNumber,unsigned int ulSerialNumberLen,
	unsigned int ulNotBefore, unsigned int ulNotAfter, 
	unsigned char * pbX509Cert, unsigned int * puiX509CertLen)
{
	unsigned int       rv = -1;
	EVP_PKEY	*pktmp = NULL;			// req�еĹ�Կ
	X509		*x509 = NULL;
	X509_NAME	*name =NULL;
	X509_REQ *req = NULL;
	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;
	BIGNUM * bnSN = NULL;

	ptr_in = pbCSR;
	
	req = d2i_X509_REQ(NULL, &ptr_in, ulCSRLen);
	if (NULL == req)
	{
		goto err;
	}
	
	// �õ�req�еĹ�Կ
	if((pktmp=X509_REQ_get_pubkey(req)) == NULL)
	{
		//goto err;
		pktmp = OpenSSL_NewEVP_PKEY_OF_SM2_PublicKey(
			req->req_info->pubkey->public_key->data + 1,
			SM2_BYTES_LEN,
			req->req_info->pubkey->public_key->data + 1 + SM2_BYTES_LEN,
			SM2_BYTES_LEN
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
	//ASN1_INTEGER_set(X509_get_serialNumber(x509), ulSerialNumber);

	BN_bin2bn(pbSerialNumber, ulSerialNumberLen, bnSN);
	BN_to_ASN1_INTEGER(bnSN,X509_get_serialNumber(x509));


	//设置有效期
	X509_gmtime_adj(X509_get_notBefore(x509), (long)(ulNotBefore*60*60*24));
	X509_gmtime_adj(X509_get_notAfter(x509), (long)(ulNotAfter*60*60*24));

	// 设置公钥
	X509_set_pubkey(x509, pktmp);


	// subject name
	name = X509_REQ_get_subject_name(req);

	// ������
	X509_set_subject_name(x509, name);

	// �䷢��
	X509_set_issuer_name(x509, name);

	// ���������չ��Ϣ
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

unsigned int OpenSSL_SM2GenCert(const unsigned char * pbCSR,unsigned int ulCSRLen,
	const unsigned char * pbX509CACert, unsigned int ulX509CACertLen, 
	unsigned char * pbSerialNumber,unsigned int ulSerialNumberLen,
	unsigned int ulNotBefore, unsigned int ulNotAfter, unsigned int ulSignFlag,
	unsigned char * pbX509Cert, unsigned int * puiX509CertLen)
{
	char * strBaseKeyUsage = NULL;
	char * strExtKeyUsage = "";
	EVP_PKEY	*pktmp = NULL;			                // req�еĹ�Կ
	X509		*x509 = NULL , *xCAcert = NULL;			// ���ɵ�֤��
	X509_NAME	*name = NULL;
	int isCACert = 0;
	X509_REQ *req = NULL;
	unsigned int rv = -1;
	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;
	BIGNUM * bnSN = NULL;

	if (OpenSSL_SM2VerifyCSR(pbCSR,ulCSRLen, 0))
	{
		goto err;
	}


	xCAcert = d2i_X509(NULL,&pbX509CACert, ulX509CACertLen);

	req = d2i_X509_REQ(NULL, &pbCSR, ulCSRLen);

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	if (NULL == req)
	{
		goto err;
	}

	if(0 == ulSignFlag)
	{
		strBaseKeyUsage = "nonRepudiation,digitalSignature";
	}
	else
	{
		strBaseKeyUsage = "keyEncipherment,dataEncipherment";
	}

	if((pktmp=X509_REQ_get_pubkey(req)) == NULL)
	{
		//goto err;
		pktmp = OpenSSL_NewEVP_PKEY_OF_SM2_PublicKey(
			req->req_info->pubkey->public_key->data + 1,
			SM2_BYTES_LEN,
			req->req_info->pubkey->public_key->data + 1 + SM2_BYTES_LEN,
			SM2_BYTES_LEN
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
	//ASN1_INTEGER_set(X509_get_serialNumber(x509), ulSerialNumber);

	BN_bin2bn(pbSerialNumber, ulSerialNumberLen, bnSN);
	BN_to_ASN1_INTEGER(bnSN,X509_get_serialNumber(x509));

	// ��Ч��
	X509_gmtime_adj(X509_get_notBefore(x509), (long)(ulNotBefore*60*60*24));
	X509_gmtime_adj(X509_get_notAfter(x509), (long)(ulNotAfter*60*60*24));

	FILE_LOG_STRING(file_log_name, "7");

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	// ������
	if(!X509_set_subject_name(x509, X509_REQ_get_subject_name(req)))
		goto err;

	// �䷢��
	if(!X509_set_issuer_name(x509, X509_get_subject_name(xCAcert)))
		goto err;

	// ���ù�Կ
	if(!X509_set_pubkey(x509, pktmp))
		goto err;

	FILE_LOG_STRING(file_log_name, "8");

	// ����req�Դ���չ��Ϣ
	if(!copy_extensions(x509, req, EXT_COPY_ALL))
		goto err;

	//�������� Note if the CA option is false the pathlen option should be omitted. 
	if(isCACert == 0)
		Add_Ext(x509, x509, NID_basic_constraints, "critical,CA:FALSE,pathlen:1");
	else if(isCACert == 1)
		Add_Ext(x509, x509, NID_basic_constraints, "critical,CA:TRUE,pathlen:1");

	//������Կ��ʾ��--------����ӵ���߶����Կ
	Add_Ext(x509, x509, NID_subject_key_identifier, "hash");

	//Authority��Կ��ʾ��----���ַ������ж��ǩ����Կʱ
	Add_Ext(x509, xCAcert, NID_authority_key_identifier, "keyid,issuer:always");

	FILE_LOG_STRING(file_log_name, "9");

	// ��Կ��;
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


unsigned int OpenSSL_SM2GenCertEX(const unsigned char * pbCSR,unsigned int ulCSRLen,
	const unsigned char * pbPublicKeyX,  unsigned int ulPublicKeyXLen, 
	const unsigned char * pbPublicKeyY,  unsigned int ulPublicKeyYLen,
	const unsigned char * pbX509CACert, unsigned int ulX509CACertLen, 
	unsigned char * pbSerialNumber,unsigned int ulSerialNumberLen,
	unsigned int ulNotBefore, unsigned int ulNotAfter, unsigned int ulSignFlag,
	unsigned char * pbX509Cert, unsigned int * puiX509CertLen)
{
	char * strBaseKeyUsage = NULL;
	char * strExtKeyUsage = "";
	EVP_PKEY	*pktmp = NULL;			// req�еĹ�Կ
	X509		*x509 = NULL , *xCAcert = NULL;			// ���ɵ�֤��
	X509_NAME	*name = NULL;
	int isCACert = 0;
	X509_REQ *req = NULL;
	unsigned int rv = -1;
	const unsigned char * ptr_in = NULL;
	unsigned char * ptr_out = NULL;
	BIGNUM * bnSN = NULL;

	if (OpenSSL_SM2VerifyCSR(pbCSR,ulCSRLen, 0))
	{
		goto err;
	}

	xCAcert = d2i_X509(NULL,&pbX509CACert, ulX509CACertLen);

	req = d2i_X509_REQ(NULL, &pbCSR, ulCSRLen);

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	if (NULL == req)
	{
		goto err;
	}

	if(0 == ulSignFlag)
	{
		strBaseKeyUsage = "nonRepudiation,digitalSignature";
	}
	else
	{
		strBaseKeyUsage = "keyEncipherment,dataEncipherment";
	}

	// �õ�req�еĹ�Կ
	if((pktmp=OpenSSL_NewEVP_PKEY_OF_SM2_PublicKey(pbPublicKeyX,ulPublicKeyXLen,pbPublicKeyY,ulPublicKeyYLen)) == NULL)
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
	//ASN1_INTEGER_set(X509_get_serialNumber(x509), ulSerialNumber);

	BN_bin2bn(pbSerialNumber, ulSerialNumberLen, bnSN);
	BN_to_ASN1_INTEGER(bnSN,X509_get_serialNumber(x509));

	// ��Ч��
	X509_gmtime_adj(X509_get_notBefore(x509), (long)(ulNotBefore*60*60*24));
	X509_gmtime_adj(X509_get_notAfter(x509), (long)(ulNotAfter*60*60*24));

	FILE_LOG_STRING(file_log_name, "7");

	FILE_LOG_FMT(file_log_name, "%s %d", __FUNCTION__, __LINE__);

	// ������
	if(!X509_set_subject_name(x509, X509_REQ_get_subject_name(req)))
		goto err;

	// �䷢��
	if(!X509_set_issuer_name(x509, X509_get_subject_name(xCAcert)))
		goto err;

	// ���ù�Կ
	if(!X509_set_pubkey(x509, pktmp))
		goto err;

	FILE_LOG_STRING(file_log_name, "8");

	// ����req�Դ���չ��Ϣ
	if(!copy_extensions(x509, req, EXT_COPY_ALL))
		goto err;

	//�������� Note if the CA option is false the pathlen option should be omitted. 
	if(isCACert == 0)
		Add_Ext(x509, x509, NID_basic_constraints, "critical,CA:FALSE,pathlen:1");
	else if(isCACert == 1)
		Add_Ext(x509, x509, NID_basic_constraints, "critical,CA:TRUE,pathlen:1");

	//������Կ��ʾ��--------����ӵ���߶����Կ
	Add_Ext(x509, x509, NID_subject_key_identifier, "hash");

	//Authority��Կ��ʾ��----���ַ������ж��ǩ����Կʱ
	Add_Ext(x509, xCAcert, NID_authority_key_identifier, "keyid,issuer:always");

	FILE_LOG_STRING(file_log_name, "9");

	// ��Կ��;
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

unsigned int OpenSSL_CertGetSubject(const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
	unsigned char * pbSubject, unsigned int * puiSubjectLen)
{
	X509 * x509 =  NULL;
	X509_NAME * pX509_Name_Subject = NULL;
	unsigned int rv = -1;

	x509 = d2i_X509( NULL, (const unsigned char **)&pbX509Cert,ulX509CertLen);
	if (!x509)
	{	
		goto err;
	}

	pX509_Name_Subject = X509_get_subject_name(x509);
	if (!pX509_Name_Subject)
	{	
		goto err;
	}

	if (!puiSubjectLen)
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	if (!pbSubject)
	{
		* puiSubjectLen = pX509_Name_Subject->bytes->length;
	}
	else if(* puiSubjectLen < pX509_Name_Subject->bytes->length)
	{
		* puiSubjectLen = pX509_Name_Subject->bytes->length;
		rv = OPE_ERR_BUFF_SMALL;
		goto err;
	}
	else
	{
		* puiSubjectLen = pX509_Name_Subject->bytes->length;
		memcpy(pbSubject, pX509_Name_Subject->bytes->data, * puiSubjectLen);
	}

	rv = 0;
err:

	if(x509)
	{
		X509_free(x509);
	}

	return rv;
}

unsigned int OpenSSL_SM2SignDigest(const unsigned char *pbHash, unsigned int ulHashLen, 
	const unsigned char *pbPrivateKey, unsigned int ulPrivateKeyLen,
	unsigned char *pbSig, unsigned int * puiSigLen
	)
{
	unsigned int rv = -1;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL, *r = NULL, *order = NULL, *order2 = NULL, *x1 = NULL, *s = NULL;
	BIGNUM *bnOne = NULL, *bnDigest = NULL, *bnPrikey = NULL , *bnTemp = NULL;
	EC_POINT *tmp_point = NULL;
	unsigned char bR[SM2_BYTES_LEN], bS[SM2_BYTES_LEN];
	int rLen, sLen;

	if(!g_group)
	{
		rv = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!pbHash || 0==ulHashLen || !pbPrivateKey || 0==ulPrivateKeyLen || !puiSigLen)
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	if(NULL == pbSig)
	{
		*puiSigLen = 2 * SM2_BYTES_LEN;
		rv = 0;    // OK
		goto err;
	}
	if(*puiSigLen < 2 * SM2_BYTES_LEN)
	{
		*puiSigLen = 2 * SM2_BYTES_LEN;
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

	BN_bin2bn(pbHash, ulHashLen, bnDigest);    // get bnDigest
	BN_bin2bn(pbPrivateKey, ulPrivateKeyLen, bnPrikey);	// get bnPrikey
	BN_one(bnOne);    //  bnOne = 1;

	tmp_point = EC_POINT_new(g_group);
	if (!tmp_point)
	{
		rv = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	// get order
	if (!EC_GROUP_get_order(g_group, order, ctx))
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
		if (!EC_POINT_mul(g_group, tmp_point, k, NULL, NULL, ctx)) 
		{
			rv = -1;
			goto err;
		}
		if (!EC_POINT_get_affine_coordinates_GFp(g_group, tmp_point, x1, NULL, ctx))
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
	memset(pbSig, 0x00,  2 * SM2_BYTES_LEN);
	memcpy(pbSig + SM2_BYTES_LEN - rLen, bR, rLen);
	memcpy(pbSig + 2*SM2_BYTES_LEN - sLen, bS, sLen);
	*puiSigLen = 2 * SM2_BYTES_LEN;

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


unsigned int OpenSSL_SM2VerifyDigest(const unsigned char *pbHash, unsigned int ulHashLen, 
	const unsigned char *pbSig, unsigned int ulSigLen,
	const unsigned char *aPubkeyValueX, unsigned int ulPublicKeyXLen,
	const unsigned char *aPubkeyValueY, unsigned int ulPublicKeyYLen)
{
	unsigned int rv = -1;
	BN_CTX *ctx = NULL;
	BIGNUM *t = NULL, *r = NULL, *r2 = NULL, *order = NULL, *x1 = NULL, *s = NULL;
	BIGNUM *bnDigest = NULL;
	EC_POINT *pubkey = NULL, *point = NULL;
	unsigned char *bR, *bS;   // bR, bS needn't free
	EC_GROUP * group = g_group;
	BIGNUM *pubkey_x = NULL, * pubkey_y = NULL; 

	if(!group)
	{
		rv = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!pbHash || 0==ulHashLen 
		|| !pbSig || ((2*SM2_BYTES_LEN)!=ulSigLen)
		|| !aPubkeyValueX || 0==ulPublicKeyXLen
		|| !aPubkeyValueY || 0==ulPublicKeyYLen)
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

	BN_bin2bn(pbHash, ulHashLen, bnDigest);    // get bnDigest

	bR=(unsigned char *)pbSig;
	bS=(unsigned char *)pbSig+SM2_BYTES_LEN;

	BN_bin2bn(bR, SM2_BYTES_LEN, r);
	BN_bin2bn(bS, SM2_BYTES_LEN, s);

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
	pubkey_x = BN_bin2bn( aPubkeyValueX,ulPublicKeyXLen, NULL );
	if (NULL == pubkey_x)
	{
		goto err;
	} 

	pubkey_y = BN_bin2bn( aPubkeyValueY,ulPublicKeyYLen, NULL );
	if ( NULL == pubkey_y)
	{
		goto err;
	} 

	EC_POINT_set_affine_coordinates_GFp(g_group,pubkey,pubkey_x,pubkey_y,ctx);

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

unsigned int OpenSSL_AddNameByID(X509_NAME * aX509Name,  unsigned int aType, unsigned char * aDataValue, unsigned int aDataLen, unsigned int aDataType)//��Ӣ�Ĵ���
{
	unsigned int rv = -1;
	unsigned char * ptr = 0;
	unsigned int i = 0;

	ptr = aDataValue;

	if (0 == aDataLen)
	{
		return 0;
	}

	if (0 == aDataType)
	{
		aDataType = MBSTRING_UTF8; 
	}

	else
	{
		aDataType = MBSTRING_BMP;

		for (i = 0; i < aDataLen; i+=2)
		{
			ptr[i] = ptr[i]^ptr[i+1];
			ptr[i+i] = ptr[i]^ptr[i+1];
			ptr[i] = ptr[i]^ptr[i+1];
		}
	}

	rv = X509_NAME_add_entry_by_NID(aX509Name,aType,aDataType,aDataValue,aDataLen,-1,0);

	return rv;
}


unsigned int OpenSSL_AddNameByName(X509_NAME * aX509Name, const char * aType, unsigned char * aDataValue, unsigned int aDataLen, unsigned int aDataType)//��Ӣ�Ĵ���
{
	unsigned int rv = -1;
	unsigned char * ptr = 0;
	unsigned int i = 0;

	ptr = aDataValue;

	if (0 == aDataLen)
	{
		return 0;
	}

	if (0 == aDataType)
	{
		aDataType = MBSTRING_UTF8; 
	}
	else
	{
		aDataType = MBSTRING_BMP;

		for (i = 0; i < aDataLen; i+=2)
		{
			ptr[i] = ptr[i]^ptr[i+1];
			ptr[i+1] = ptr[i]^ptr[i+1];
			ptr[i] = ptr[i]^ptr[i+1];
		}
	}

	rv = X509_NAME_add_entry_by_txt(aX509Name,aType,aDataType,aDataValue,aDataLen,-1,0);

	return rv;
}


unsigned int OpenSSL_CertGetPubkey(const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
	unsigned char * pbPublicKey, unsigned int * puiPublicKeyLen)
{
	X509 * x509 =  NULL;
	int rv = -1;
	ASN1_BIT_STRING *pubkey = NULL;

	x509 = d2i_X509( NULL, (const unsigned char **)&pbX509Cert,ulX509CertLen);
	if (!x509)
	{	
		rv = -1;
		goto err;
	}

	//��ȡ��Կ
	pubkey = X509_get0_pubkey_bitstr(x509);   //�õ�pubkey
	if(!pubkey)
	{
		rv = -2;
		goto err;
	}

	if (!pbPublicKey)
	{
		* puiPublicKeyLen = pubkey->length;
	}
	else if(* puiPublicKeyLen < pubkey->length)
	{
		rv = -4;
		goto err;
	}
	else
	{
		memcpy(pbPublicKey, pubkey->data,pubkey->length);

		FILE_LOG_STRING(file_log_name,"aPubkeyValue1");
		FILE_LOG_NUMBER(file_log_name,pubkey->length);
		FILE_LOG_HEX(file_log_name,pbPublicKey,pubkey->length);

		* puiPublicKeyLen = pubkey->length;

		FILE_LOG_STRING(file_log_name,"pubkey->data");
		FILE_LOG_NUMBER(file_log_name,pubkey->length);
		FILE_LOG_HEX(file_log_name,pubkey->data,pubkey->length);


		FILE_LOG_STRING(file_log_name,"aPubkeyValue2");
		FILE_LOG_NUMBER(file_log_name,pubkey->length);
		FILE_LOG_HEX(file_log_name,pbPublicKey,pubkey->length);

	}

	rv = 0;
err:
	if(x509)
	{
		X509_free(x509);
	}

	return rv;
}

/*
*	��֤���м���req�Դ���չ��Ϣ
*/
int copy_extensions(X509 *x, X509_REQ *req, int copy_type)
{
	STACK_OF(X509_EXTENSION) *exts = NULL;
	X509_EXTENSION *ext, *tmpext;
	ASN1_OBJECT *obj;
	int i, idx, ret = 0;
	if (!x || !req || (copy_type == EXT_COPY_NONE))
		return 1;
	exts = X509_REQ_get_extensions(req);

	for(i = 0; i < sk_X509_EXTENSION_num(exts); i++)
	{
		ext = sk_X509_EXTENSION_value(exts, i);
		obj = X509_EXTENSION_get_object(ext);
		idx = X509_get_ext_by_OBJ(x, obj, -1);
		/* Does extension exist? */
		if (idx != -1) 
		{
			/* If normal copy don't override existing extension */
			if (copy_type == EXT_COPY_ADD)
				continue;
			/* Delete all extensions of same type */
			do
			{
				tmpext = X509_get_ext(x, idx);
				X509_delete_ext(x, idx);
				X509_EXTENSION_free(tmpext);
				idx = X509_get_ext_by_OBJ(x, obj, -1);
			} while (idx != -1);
		}
		if (!X509_add_ext(x, ext, -1))
			goto err;
	}

	ret = 1;

err:

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return ret;
}


short Add_Ext(X509 *cert, X509 * root, int nid, char *value)
{
	X509_EXTENSION *ex;
	X509V3_CTX ctx;

	X509V3_set_ctx(&ctx, root, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex)
		return -1;

	X509_add_ext(cert,ex,-1);
	X509_EXTENSION_free(ex);

	return 1;
}

unsigned int OpenSSL_SM2GenCRL(const OPST_CRL * pstCRLList, unsigned int ulCRLListSize, 
	const unsigned char * pbX509Cert,unsigned int ulX509CertLen, 
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

	x509 = d2i_X509(NULL ,&in_ptr,ulX509CertLen );
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

	for (i = 0; i < ulCRLListSize; i++) 
	{
		prevtm[i] = ASN1_UTCTIME_new();
		rtmp[i] = ASN1_ENUMERATED_new();
		tmpser[i] = ASN1_INTEGER_new();
		r[i] = X509_REVOKED_new();

		if (NULL == prevtm[i] || NULL == rtmp[i] || NULL == r[i] || NULL == tmpser[i])
		{
			goto err;
		}

		// ʱ��
		ASN1_UTCTIME_set(prevtm[i], pstCRLList[i].dt);

		if (!X509_REVOKED_set_revocationDate(r[i], prevtm[i]))
		{
			goto err;
		}

		// ԭ��
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

	for (i = 0; i < ulCRLListSize; i++) 
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

#define ENTRY_COUNT  7  

struct entry {  
	int key;  
	char *name;  
};  

static const struct entry nids[ENTRY_COUNT] = {  
	{NID_countryName, "countryName"},  
	{NID_stateOrProvinceName, "stateOrProvinceName"},  
	{NID_localityName, "localityName"},  
	{NID_organizationName, "organiationName"},  
	{NID_organizationalUnitName, "organizationalUnitName"},  
	{NID_commonName, "commonName"},  
	{NID_pkcs9_emailAddress, "emailAddress"},  
};

unsigned int OpenSSL_CertGetSubjectItem(const unsigned char * pbX509Cert, unsigned int ulX509CertLen,int ulIndex, unsigned char * pbSubjectItem, unsigned int * puiSubjectItemLen)
{
	X509 * x509 =  NULL;
	X509_NAME * pX509_Name_Subject = NULL;
	unsigned int rv = -1;

	int j = 0;  
	int pos = -1;  
	ASN1_STRING *d = NULL;

	FILE_LOG_STRING(file_log_name,"1");

	x509 = d2i_X509( NULL, (const unsigned char **)&pbX509Cert,ulX509CertLen);
	if (!x509)
	{	
		goto err;
	}
	FILE_LOG_STRING(file_log_name,"2");
	pX509_Name_Subject = X509_get_subject_name(x509);
	if (!pX509_Name_Subject)
	{	
		goto err;
	}

	/*j = X509_NAME_entry_count(pX509_Name_Subject);  

	for (i = 0; i < ENTRY_COUNT; i++) {  
	pos = -1;  

	for (;;) 
	{
	pos = X509_NAME_get_index_by_NID(pX509_Name_Subject, nids[i].key, pos);  

	if (pos == -1)
	{
	break;
	}

	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(pX509_Name_Subject, pos)); 
	printf("%s = %s [%d]\n", nids[i].name, d->data, d->length);  

	FILE_LOG_STRING(file_log_name,nids[i].name);
	FILE_LOG_NUMBER(file_log_name,d->length);
	FILE_LOG_HEX(file_log_name,d->data, d->length);
	FILE_LOG_BYTE(file_log_name,d->data, d->length);
	}
	}*/

	pos = -1;  
	FILE_LOG_STRING(file_log_name,"3");
	pos = X509_NAME_get_index_by_NID(pX509_Name_Subject, nids[ulIndex].key, pos);  
	FILE_LOG_STRING(file_log_name,"4");
	if (pos == -1)
	{
		rv = -1;
		goto err;
	}
	FILE_LOG_STRING(file_log_name,"5");
	d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(pX509_Name_Subject, pos)); 
	printf("%s = %s [%d]\n", nids[ulIndex].name, d->data, d->length);  
	FILE_LOG_STRING(file_log_name,nids[ulIndex].name);
	FILE_LOG_NUMBER(file_log_name,d->length);
	FILE_LOG_HEX(file_log_name,d->data, d->length);
	FILE_LOG_BYTE(file_log_name,d->data, d->length);


	if (!puiSubjectItemLen)
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	if (!pbSubjectItem)
	{
		* puiSubjectItemLen = d->length;
	}
	else if(* puiSubjectItemLen < d->length)
	{
		* puiSubjectItemLen = d->length;
		rv = OPE_ERR_BUFF_SMALL;
		goto err;
	}
	else
	{
		* puiSubjectItemLen = d->length;
		memcpy(pbSubjectItem, d->data, * puiSubjectItemLen);
	}

	rv = 0;
err:

	return rv;
}

unsigned int OpenSSL_CertExtenItem(const unsigned char * pbX509Cert, unsigned int ulX509CertLen,int ulIndex, unsigned char * pbSubjectItem, unsigned int * puiSubjectItemLen)
{
	X509 * x509 =  NULL;
	X509_EXTENSION * exten = NULL;
	unsigned int rv = -1;

	int j = 0;  
	int pos = -1;  
	ASN1_STRING *d = NULL;

	x509 = d2i_X509( NULL, (const unsigned char **)&pbX509Cert,ulX509CertLen);
	if (!x509)
	{	
		goto err;
	}

	for (j = 0; j< X509v3_get_ext_count(x509->cert_info->extensions);j++)
	{
		exten = X509v3_get_ext(x509->cert_info->extensions,j);

		FILE_LOG_FMT(file_log_name,"%d exten->critical", j);
		FILE_LOG_NUMBER(file_log_name,exten->critical);

		FILE_LOG_FMT(file_log_name,"%d exten->object", j);
		FILE_LOG_HEX(file_log_name,exten->object->data,exten->object->length);

		FILE_LOG_FMT(file_log_name,"%d exten->value", j);
		FILE_LOG_HEX(file_log_name,exten->value->data, exten->value->length);
	}

	rv = 0;
err:

	return rv;
}

unsigned int OpenSSL_SM2Decrypt(const unsigned char * pbPrivateKey, unsigned int ulPrivateKeyLen, const unsigned char * pbIN, unsigned int ulINLen,
	unsigned char * pbOUT, unsigned int * puiOUTLen)
{
	unsigned char * szData = NULL;
	unsigned int szLen = BUFFER_LEN_1K * BUFFER_LEN_1K;
	unsigned int ulRet = -1;

	if(!pbIN || !pbPrivateKey)
	{
		return -1;
	}


	ulRet = OpenSSL_SM2DecryptInner((unsigned char *)pbIN, ulINLen, (unsigned char *)pbPrivateKey, ulPrivateKeyLen, szData, &szLen);

	if(ulRet)
	{
		goto err;
	}

	szData = malloc(szLen);
	memset(szData, 0, szLen);

	ulRet = OpenSSL_SM2DecryptInner((unsigned char *)pbIN, ulINLen, (unsigned char *)pbPrivateKey, ulPrivateKeyLen, szData, &szLen);

	if (ulRet)
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
	
	return ulRet;
}

unsigned int OpenSSL_SM2Encrypt(const unsigned char * pbPublicKeyX, unsigned int ulPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int ulPublicKeyYLen,
	const unsigned char * pbIN, unsigned int ulINLen,
	unsigned char * pbOUT, unsigned int * puiOUTLen)
{
	unsigned char * szData = NULL;
	unsigned int szLen = BUFFER_LEN_1K * BUFFER_LEN_1K;
	unsigned int ulRet = -1;

	unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
	unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

	if(!pbIN || !pbPublicKeyX || !pbPublicKeyY)
	{
		return -1;
	}

	memcpy(pubkey_xy_value, "\x04", 1);
	memcpy(pubkey_xy_value + 1 , pbPublicKeyX, SM2_BYTES_LEN);
	memcpy(pubkey_xy_value + 1 + SM2_BYTES_LEN, pbPublicKeyY, SM2_BYTES_LEN);

	//ulRet = tcm_ecc_encrypt((unsigned char *)pbIN, ulINLen, (unsigned char *)pubkey_xy_value, pubkey_xy_len, szData, &szLen);
	ulRet = OpenSSL_SM2EncryptInner(pbIN,ulINLen,pbPublicKeyX,ulPublicKeyXLen,pbPublicKeyY,ulPublicKeyYLen,szData,&szLen);

	if(ulRet)
	{
		goto err;
	}

	szData = malloc(szLen);
	memset(szData, 0, szLen);

	//ulRet = tcm_ecc_encrypt((unsigned char *)pbIN, ulINLen, (unsigned char *)pubkey_xy_value, pubkey_xy_len, szData, &szLen);
	ulRet = OpenSSL_SM2EncryptInner(pbIN,ulINLen,pbPublicKeyX,ulPublicKeyXLen,pbPublicKeyY,ulPublicKeyYLen,szData,&szLen);

	if (ulRet)
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

	return ulRet;
}




unsigned int OpenSSL_SM2Point(const unsigned char * pbPublicKeyX, unsigned int ulPublicKeyXLen, 
	const unsigned char * pbPublicKeyY, unsigned int ulPublicKeyYLen
	)
{
	unsigned int ulRet = 0;
	unsigned char data_value[SM2_BYTES_LEN * 2 +1] = {0};

	data_value[0] = 0x04;

	memcpy(data_value + 1,pbPublicKeyX, ulPublicKeyXLen);
	memcpy(data_value + 1 + ulPublicKeyXLen,pbPublicKeyY, ulPublicKeyYLen);

	if (tcm_ecc_is_point_valid(data_value,sizeof(data_value)))
	{
		ulRet = 0;
	}
	else
	{
		ulRet = -1;
	}

	return ulRet;
}


unsigned int OpenSSL_SM2Write(const unsigned char * pbIN, unsigned int ulINLen, 
	unsigned int ulType,char * szFileName,unsigned int fileEncode, char * szPassword
	)
{
	unsigned int ulRet = -1;

	FILE * file = fopen(szFileName, "w");

	if(NULL == file)
	{
		goto err;
	}

	switch(ulType)
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

			if(ulINLen != SM2_BYTES_LEN)
			{
				ulRet = -1;
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

			if (!(EC_KEY_set_group(ec, g_group)))
			{
				goto err;
			}

			if (!EC_KEY_generate_key(ec))
			{
				goto err;
			}

			/* set private key */
			prvkey = BN_bin2bn( pbIN,ulINLen, NULL );
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
			ulRet = 0;
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

			x509 = d2i_X509(NULL,&ptr_in,ulINLen);

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
			ulRet = 0;
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

			if(ulINLen != SM2_BYTES_LEN * 2)
			{
				ulRet = -1;
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

			if (!(EC_KEY_set_group(ec, g_group)))
			{
				goto err;
			}

			if (!(pubkey = EC_POINT_new(g_group)))
			{ 
				goto err;
			}

			if (!EC_KEY_generate_key(ec))
			{
				goto err;
			}

			/* set public key */
			pubkey_x = BN_bin2bn( pbIN,SM2_BYTES_LEN, NULL );
			if (NULL == pubkey_x)
			{
				goto err;
			} 

			pubkey_y = BN_bin2bn( pbIN+SM2_BYTES_LEN,SM2_BYTES_LEN, NULL );
			if ( NULL == pubkey_y)
			{
				goto err;
			} 

			if ( !EC_POINT_set_affine_coordinates_GFp(g_group, pubkey, pubkey_x, pubkey_y, ctx) )
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
			ulRet = 0;

		}
		break;
	default:
		break;
	}

err:
	if (file)
	{
		fclose(file);
	}
	
	return ulRet;
}



unsigned int OpenSSL_SM2DecryptInner(const unsigned char *pbIN, unsigned int ulINLen, 
	const unsigned char *pbPrivateKey, unsigned int ulPrivateKeyLen, 
	unsigned char *pbOUT, unsigned int * puiOUTLen)
{
	unsigned int ulRet = -1;

	unsigned int ulPlainTextLen = 0;

	unsigned char * c1 = NULL; 
	unsigned char * c2 = NULL;
	unsigned char * c3 = NULL;
	unsigned char * t = NULL;
	unsigned char * zero_buffer = NULL;
	unsigned char * data_value_out = NULL;
	unsigned char data_value_digest[SM3_DIGEST_LEN] = {0};
	unsigned int data_len_digest = SM3_DIGEST_LEN;

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
	unsigned char x2y2[2*SM2_BYTES_LEN] = {0};

	sch_context sm3Ctx;


	int i = 0;

	if (!pbIN || ulINLen < (2*SM2_BYTES_LEN+1+SM3_DIGEST_LEN) || !puiOUTLen
		|| !pbPrivateKey || ulPrivateKeyLen != SM2_BYTES_LEN)
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	ulPlainTextLen = ulINLen  -( 2*SM2_BYTES_LEN + 1 + SM3_DIGEST_LEN);

	if(!pbOUT)
	{
		*puiOUTLen = ulPlainTextLen;
		ulRet = 0;  // OK
		goto err;
	}
	if(*puiOUTLen < ulPlainTextLen)
	{
		*puiOUTLen = ulPlainTextLen;
		ulRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	if(!g_group)
	{
		ulRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	ctx = BN_CTX_new();
	if (!ctx) 
	{
		ulRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	BN_CTX_start(ctx);

	C1 = EC_POINT_new(g_group);
	S = EC_POINT_new(g_group);

	if (!C1 || !S)
	{
		ulRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	privatekey = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);

	if( !privatekey || !h || !x2 || !y2)
	{
		ulRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	if (!EC_GROUP_get_cofactor(g_group, h, ctx)) 
	{
		ulRet = -1;
		goto err;
	}

	t = (unsigned char *)OPENSSL_malloc(ulPlainTextLen);
	zero_buffer = (unsigned char *)OPENSSL_malloc(ulPlainTextLen);
	data_value_out = (unsigned char *)OPENSSL_malloc(ulPlainTextLen);

	memset(zero_buffer, 0, ulPlainTextLen);

	c1 = (unsigned char *)pbIN + 1;
	c2 = (unsigned char *)pbIN + SM2_BYTES_LEN * 2 + 1;
	c3 = (unsigned char *)pbIN + SM2_BYTES_LEN * 2 + 1 + ulPlainTextLen;

	// 第一步 
	// 从密文中取出C1
	pubkey_x_C1 = BN_bin2bn( c1,SM2_BYTES_LEN, NULL );
	if (NULL == pubkey_x_C1)
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	pubkey_y_C1 = BN_bin2bn( c1 + SM2_BYTES_LEN,SM2_BYTES_LEN, NULL );
	if ( NULL == pubkey_y_C1)
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	if (!EC_POINT_set_affine_coordinates_GFp(g_group, C1, pubkey_x_C1, pubkey_y_C1, ctx) )
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 
	// 判断C1是否满足曲线方程
	if(!EC_POINT_is_on_curve(g_group, C1, ctx))
	{
		ulRet = -1;
		goto err;
	}

	// 第二步
	// 计算椭圆曲线点S=[h]C1
	if(!EC_POINT_mul(g_group,S,NULL,C1,h,ctx))
	{
		ulRet = -1;
		goto err;
	}

	// S=O?
	if (EC_POINT_is_at_infinity(g_group, S)) 
	{
		ulRet = -1;
		goto err;
	}

	// 第三步
	// 计算[db]C1=(x2,y2)=C2=S
	BN_bin2bn(pbPrivateKey, ulPrivateKeyLen ,privatekey);
	if(!EC_POINT_mul(g_group,S,NULL,C1,privatekey,ctx))
	{
		ulRet = -1;
		goto err;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(g_group, S, x2, y2, ctx))
	{
		ulRet = -1;
		goto err;
	}

	x2Len = BN_num_bytes(x2);
	y2Len = BN_num_bytes(y2);
	if( (x2Len>SM2_BYTES_LEN) || (x2Len>SM2_BYTES_LEN) )
	{
		ulRet = -1;
		goto err;
	}

	// 前补00
	x2Len = BN_bn2bin(x2, x2y2 + SM2_BYTES_LEN - x2Len);
	y2Len = BN_bn2bin(y2, x2y2 + 2*SM2_BYTES_LEN - y2Len);

	// 第四步
	// 计算t = KDF(x2||y2,klen)

	ulRet = tcm_kdf(t,ulPlainTextLen,x2y2,sizeof(x2y2));
	if(ulRet)
	{
		goto err;
	}

	// t全0
	if (0 == memcmp(zero_buffer,t,ulPlainTextLen))
	{
		ulRet = -1;
		goto err;
	}

	// 第五步
	// M'=C2^t
	for(i = 0; i < ulPlainTextLen; i++)
	{
		data_value_out[i] = t[i]^c2[i];
	}


	// 第六步
	// u = HASH(x2||M'||y2)
	memset(&sm3Ctx,0x00,sizeof(sm3Ctx));
	tcm_sch_starts(&sm3Ctx);
	tcm_sch_update(&sm3Ctx, x2y2, SM2_BYTES_LEN);
	tcm_sch_update(&sm3Ctx, (unsigned char *)data_value_out, ulPlainTextLen);
	tcm_sch_update(&sm3Ctx, x2y2+SM2_BYTES_LEN, SM2_BYTES_LEN);
	tcm_sch_finish(&sm3Ctx, data_value_digest);

	if (0 == memcmp(c3,data_value_digest,SM3_DIGEST_LEN))
	{
		ulRet = 0;
		*puiOUTLen = ulPlainTextLen;
		memcpy(pbOUT,data_value_out,ulPlainTextLen);
	}
	else
	{
		ulRet = -1;
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

	return ulRet;
}



unsigned int OpenSSL_SM2EncryptInner(
	const unsigned char *pbIN, unsigned int ulINLen, 
	const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen, 
	const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen, 
	unsigned char *pbOUT, unsigned int * puiOUTLen
	)
{
	unsigned int ulRet = -1;
	unsigned int ulCiphertextLen = 0;
	BN_CTX * ctx = NULL;
	EC_POINT * pubkey_xy = NULL;
	EC_POINT * C1 = NULL;
	EC_POINT * S = NULL;

	unsigned char x2y2[SM2_BYTES_LEN * 2] = {0};

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

	sch_context sm3Ctx;

	// 判断是否初始化OPENSSL GROUP
	if(!g_group)
	{
		ulRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	// 判断参数是否正确
	if(NULL == pbIN || 0 == ulINLen || NULL == pbPublicKeyX
		|| NULL == pbPublicKeyY || SM2_BYTES_LEN != ulPublicKeyXLen || SM2_BYTES_LEN != ulPublicKeyYLen
		|| NULL == puiOUTLen)
	{
		ulRet=OPE_ERR_INVALID_PARAM;
		goto err;
	}

	// 计算密文长度
	ulCiphertextLen =  2*SM2_BYTES_LEN + 1 + ulINLen + SM3_DIGEST_LEN;
	if(NULL == pbOUT)
	{
		*puiOUTLen = ulCiphertextLen;
		ulRet = 0;  // OK
		goto err;
	}
	if(*puiOUTLen < ulCiphertextLen)
	{
		*puiOUTLen  = ulCiphertextLen;
		ulRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	ctx = BN_CTX_new();
	if(!ctx)
	{
		ulRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	BN_CTX_start(ctx);

	pubkey_xy = EC_POINT_new(g_group);
	C1 = EC_POINT_new(g_group);
	S = EC_POINT_new(g_group);

	if(!pubkey_xy || !C1 || !S)
	{
		ulRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	order = BN_CTX_get(ctx);
	k = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);

	if( !order || !k || !h || !x2 || !y2)
	{
		ulRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	if (!EC_GROUP_get_order(g_group, order, ctx)) 
	{
		ulRet = -1;
		goto err;
	}

	if (!EC_GROUP_get_cofactor(g_group, h, ctx)) 
	{
		ulRet = -1;
		goto err;
	}

	// 初始化公钥
	pubkey_x = BN_bin2bn( pbPublicKeyX,ulPublicKeyXLen, NULL );
	if (NULL == pubkey_x)
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	pubkey_y = BN_bin2bn( pbPublicKeyY,ulPublicKeyYLen, NULL );
	if ( NULL == pubkey_y)
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	if (!EC_POINT_set_affine_coordinates_GFp(g_group, pubkey_xy, pubkey_x, pubkey_y, ctx) )
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	} 

	t = (unsigned char *)OPENSSL_malloc(ulINLen);
	c1 = (unsigned char *)OPENSSL_malloc(2*SM2_BYTES_LEN+1);
	c2 = (unsigned char *)OPENSSL_malloc(ulINLen);
	c3 = (unsigned char *)OPENSSL_malloc(SM3_DIGEST_LEN);
	zero_buffer = (unsigned char *)OPENSSL_malloc(ulINLen);

	if( !t || !c1 || !c2 || !c3 || !zero_buffer)
	{
		ulRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	memset(zero_buffer, 0, ulINLen);
	memset(c1, 0, 2*SM2_BYTES_LEN+1);
	memset(c2, 0, ulINLen);
	memset(c3, 0, SM3_DIGEST_LEN);

	for(;;)
	{

		// 第一步
		// 产生随机数
		for (;;)
		{
			if (!BN_rand_range(k, order)) 
			{
				ulRet = -1;
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
		if (!EC_POINT_mul(g_group, C1, k, NULL, NULL, ctx))
		{
			ulRet = -1;
			goto err;
		}

		if (!EC_POINT_get_affine_coordinates_GFp(g_group, C1, pubkey_x, pubkey_y, ctx) )
		{
			ulRet = OPE_ERR_INVALID_PARAM;
			goto err;
		} 

		if(!EC_POINT_is_on_curve(g_group, C1, ctx))
		{
			ulRet = -1;
			goto err;
		}

		c1[0]=0x04;
		BN_bn2bin(pubkey_x,c1+1);
		BN_bn2bin(pubkey_y,c1+1+SM2_BYTES_LEN);

		// 第三步
		// S=[h]Pb
		if (!EC_POINT_mul(g_group, S, NULL, pubkey_xy, h, ctx)) 
		{
			ulRet = -1;
			goto err;
		}
		// S=O
		if (EC_POINT_is_at_infinity(g_group, S))
		{
			ulRet = -1;
			goto err;
		}
		// 第四步
		// S=[k]Pb=(x2,y2)
		if (!EC_POINT_mul(g_group, S, NULL, pubkey_xy, k, ctx)) 
		{
			ulRet = -1;
			goto err;
		}
		// 获取x2y2
		if (!EC_POINT_get_affine_coordinates_GFp(g_group, S, x2, y2, ctx)) 
		{
			ulRet = -1;
			goto err;
		}

		memset(x2y2, 0x00, sizeof(x2y2));

		x2Len = BN_num_bytes(x2);
		y2Len = BN_num_bytes(y2);
		if( (x2Len>SM2_BYTES_LEN) || (x2Len>SM2_BYTES_LEN) )
		{
			ulRet = -1;
			goto err;
		}

		// 前补00
		x2Len = BN_bn2bin(x2, x2y2 + SM2_BYTES_LEN - x2Len);
		y2Len = BN_bn2bin(y2, x2y2 + 2*SM2_BYTES_LEN - y2Len);

		// 第五步
		// t= KDF(x2||y2,klen)
		ulRet = tcm_kdf(t, ulINLen, x2y2, 2*SM2_BYTES_LEN);

		// t全0
		if (0 == memcmp(zero_buffer,t,ulINLen))
		{
			continue;
		}else
		{
			break;
		}
	}

	// 第六步
	// C2=M^t
	for( i = 0; i< ulINLen; i++)
	{
		c2[i] = pbIN[i] ^ t[i];
	}
	// 第七步
	// C3=Hash(x2||M||y2)
	memset(&sm3Ctx,0x00,sizeof(sm3Ctx));
	tcm_sch_starts(&sm3Ctx);
	tcm_sch_update(&sm3Ctx, x2y2, SM2_BYTES_LEN);
	tcm_sch_update(&sm3Ctx, (unsigned char *)pbIN, ulINLen);
	tcm_sch_update(&sm3Ctx, x2y2+SM2_BYTES_LEN, SM2_BYTES_LEN);
	tcm_sch_finish(&sm3Ctx, c3);

	ulRet = 0;

	memcpy(pbOUT,c1, SM2_BYTES_LEN*2+1);
	memcpy(pbOUT + SM2_BYTES_LEN*2+1 , c2, ulINLen);
	memcpy(pbOUT + SM2_BYTES_LEN*2+1 + ulINLen,c3,SM3_DIGEST_LEN);

	*puiOUTLen = SM2_BYTES_LEN*2+1 + ulINLen + SM3_DIGEST_LEN;

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

	return ulRet;
}



unsigned int OpenSSL_CertGetPublicKeyAlgor(const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
	unsigned char *pbPublicKeyAlgor, unsigned int *puiPublicKeyAlgorLen
	)
{
	X509 * x509 =  NULL;
	X509_NAME * pX509_Name_Subject = NULL;
	unsigned int rv = -1;
	unsigned char * ptr_out = NULL;
	unsigned int lenPublicKeyAlgor = 0;

	x509 = d2i_X509( NULL, (const unsigned char **)&pbX509Cert,ulX509CertLen);
	if (!x509)
	{	
		goto err;
	}

	lenPublicKeyAlgor = x509->cert_info->key->algor->algorithm->length;

	if (!puiPublicKeyAlgorLen)
	{
		rv = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	if (!pbPublicKeyAlgor)
	{
		* puiPublicKeyAlgorLen = lenPublicKeyAlgor;
	}
	else if(* puiPublicKeyAlgorLen < lenPublicKeyAlgor)
	{
		* puiPublicKeyAlgorLen = lenPublicKeyAlgor;
		rv = OPE_ERR_BUFF_SMALL;
		goto err;
	}
	else
	{
		ptr_out = pbPublicKeyAlgor;
		*puiPublicKeyAlgorLen = lenPublicKeyAlgor;
		memcpy( ptr_out,x509->cert_info->key->algor->algorithm->data, * puiPublicKeyAlgorLen);
	}

	rv = 0;
err:

	if(x509)
	{
		X509_free(x509);
	}

	return rv;
}


unsigned int OpenSSL_CertSubjectCompareIssuer(const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
	unsigned int * bEqual
	)
{
	X509 * x509 =  NULL;
	X509_NAME * pX509_Name_Subject = NULL;
	X509_NAME * pX509_Name_Issuer = NULL;
	unsigned int rv = -1;

	unsigned lenCmp = 0;

	x509 = d2i_X509( NULL, (const unsigned char **)&pbX509Cert,ulX509CertLen);
	if (!x509)
	{	
		goto err;
	}

	pX509_Name_Subject = X509_get_subject_name(x509);

	pX509_Name_Issuer = X509_get_issuer_name(x509);

	lenCmp = pX509_Name_Subject->bytes->length > pX509_Name_Issuer->bytes->length ?
		pX509_Name_Subject->bytes->length : pX509_Name_Issuer->bytes->length;

	if (0 == memcmp(pX509_Name_Subject->bytes->data,pX509_Name_Issuer->bytes->data, lenCmp))
	{
		*bEqual = 1;
	}
	else
	{
		*bEqual = 0;
	}

	rv = 0;
err:

	if(x509)
	{
		X509_free(x509);
	}

	return rv;
}


