#include "openssl_certinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <string.h>
#include <string>

#include "TimeAPI.h"

using namespace std;

X509 * x509 = NULL;

extern "C" int time_print( const char ** s,
	int n,
	int min,
	int max,
	int * e
	)
{
	int retval = 0;

	while (n) {

		if (**s < '0' || **s > '9') { *e = 1; return 0; }

		retval *= 10;

		retval += **s - '0';

		--n; ++(*s);

	}

	if (retval < min || retval > max) *e = 1;

	return retval;

}

extern "C" time_t ASN1_TIME_get (ASN1_TIME * a,
	int * err
	)
{
	char days[2][12] =
	{
		{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
		{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
	};
	int dummy;
	const char *s;
	int generalized;
	struct tm t;
	int i, year, isleap, offset;
	time_t retval;

	if (err == NULL) err = &dummy;

	if (a->type == V_ASN1_GENERALIZEDTIME) {

		generalized = 1;

	} else if (a->type == V_ASN1_UTCTIME) {

		generalized = 0;

	} else {

		*err = 1;

		return 0;

	}

	s = (const char *)a->data; // Data should be always null terminated

	if (s == NULL || s[a->length] != '\0') {

		*err = 1;

		return 0;

	}

	*err = 0;

	if (generalized) {

		t.tm_year = time_print(&s, 4, 0, 9999, err) - 1900;

	} else {

		t.tm_year = time_print(&s, 2, 0, 99, err);

		if (t.tm_year < 50) t.tm_year += 100;

	}

	t.tm_mon = time_print(&s, 2, 1, 12, err) - 1;

	t.tm_mday = time_print(&s, 2, 1, 31, err);

	// NOTE: It's not yet clear, if this implementation is 100% correct

	// for GeneralizedTime... but at least misinterpretation is

	// impossible --- we just throw an exception

	t.tm_hour = time_print(&s, 2, 0, 23, err);

	t.tm_min = time_print(&s, 2, 0, 59, err);

	if (*s >= '0' && *s <= '9') {

		t.tm_sec = time_print(&s, 2, 0, 59, err);

	} else {

		t.tm_sec = 0;

	}

	if (*err) return 0; // Format violation

	if (generalized) {

		// skip fractional seconds if any

		while (*s == '.' || *s == ',' || (*s >= '0' && *s <= '9')) ++s;

		// special treatment for local time

		if (*s == 0) {

			t.tm_isdst = -1;

			retval = mktime(&t); // Local time is easy :)

			if (retval == (time_t)-1) {

				*err = 2;

				retval = 0;

			}

			return retval;

		}

	}

	if (*s == 'Z') {

		offset = 0;

		++s;

	} else if (*s == '-' || *s == '+') {

		i = (*s++ == '-');

		offset = time_print(&s, 2, 0, 12, err);

		offset *= 60;

		offset += time_print(&s, 2, 0, 59, err);

		if (*err) return 0; // Format violation

		if (i) offset = -offset;

	} else {

		*err = 1;

		return 0;

	}

	if (*s) {

		*err = 1;

		return 0;

	}


	// And here comes the hard part --- there's no standard function to

	// convert struct tm containing UTC time into time_t without

	// messing global timezone settings (breaks multithreading and may

	// cause other problems) and thus we have to do this "by hand"

	//

	// NOTE: Overflow check does not detect too big overflows, but is

	// sufficient thanks to the fact that year numbers are limited to four

	// digit non-negative values.

	retval = t.tm_sec;

	retval += (t.tm_min - offset) * 60;

	retval += t.tm_hour * 3600;

	retval += (t.tm_mday - 1) * 86400;

	year = t.tm_year + 1900;

	if (sizeof(time_t) == 4) {

		// This is just to avoid too big overflows being undetected, finer

		// overflow detection is done below.

		if (year < 1900 || year > 2040) *err = 2;

	}

	// FIXME: Does POSIX really say, that all years divisible by 4 are

	// leap years (for consistency)??? Fortunately, this problem does

	// not exist for 32-bit time_t and we should'nt be worried about

	// this until the year of 2100 :)

	isleap = ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);

	for (i = t.tm_mon - 1; i >= 0; --i) retval += days[isleap][i] * 86400;

	retval += (year - 1970) * 31536000;

	if (year < 1970) {

		retval -= ((1970 - year + 2) / 4) * 86400;

		if (sizeof(time_t) > 4) {

			for (i = 1900; i >= year; i -= 100) {

				if (i % 400 == 0) continue;

				retval += 86400;

			}

		}

		if (retval >= 0) *err = 2;

	} else {

		retval += ((year - 1970 + 1) / 4) * 86400;

		if (sizeof(time_t) > 4) {

			for (i = 2100; i < year; i += 100) {

				// The following condition is the reason to

				// start with 2100 instead of 2000

				if (i % 400 == 0) continue;
				retval -= 86400;
			}
		}
		if (retval < 0) *err = 2;
	}
	if (*err) retval = 0;
	return retval;
}


int OpenSSL_PraseCertInitialize(const unsigned char * pbX509Cert, unsigned long ulX509CertLen)
{
	//清除以前x509
	if(x509)
	{
		X509_free(x509);
		x509 = NULL;
	}

	x509 = d2i_X509(NULL, &pbX509Cert, ulX509CertLen);

	if (NULL == x509)
	{
		goto err;
	}
err:
	return 0;
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

extern "C" unsigned long OPF_Bin2Str(const unsigned char *ain_data_value,unsigned long ain_data_len,char *aout_data_value,unsigned long * aout_data_len);

int GetCertKeyUsage(X509 *cert, char *szCertKeyUsage, int *pnCertKeyUsageLen)
{  	
	unsigned char buf[255] = {0};
	char	szTmp[5] = {0};
	int len=0;
	int ext_count;
	int k;
	BIO *bio = NULL;
	char	szKeyUsage[] = "X509v3 Key Usage";

	char	*pszDest = NULL;

	*pnCertKeyUsageLen = 0;
	ext_count = X509_get_ext_count(cert);	

	for (k=0; k <ext_count; k++ )
	{
		X509_EXTENSION* ex = X509_get_ext(cert, k);
		if( ex == NULL )
		{
			continue;
		}

		memset(buf, 0, sizeof(buf));
		OBJ_obj2txt((char *)buf, sizeof(buf), ex->object, 0);
		//printf("name = %s\n", buf);
		if(0 != memcmp(buf, szKeyUsage, strlen(szKeyUsage)))
		{
			continue;
		}

		bio = BIO_new(BIO_s_mem());
		if(!X509V3_EXT_print(bio, ex, 0, 0)) // read the text of this      extention
		{
			M_ASN1_OCTET_STRING_print(bio,ex->value);
		}
		memset(buf, 0, sizeof(buf));
		len = BIO_read(bio, buf, sizeof(buf));// here buffer contain          the text, len the lenght of it.
		buf[len] = '\0'; // add the eot sign, buffer contain a readable text.
		BIO_free(bio);
		//printf("value = %s\n", buf);	
		*pnCertKeyUsageLen = len+5;	//5 = ' '+'(XX)'
		if(szCertKeyUsage)
		{
			strcpy(szCertKeyUsage, (const char*)buf);
			strcat(szCertKeyUsage, " (");
			//只取最后一个字节
			unsigned long ulOutLen = BUFFER_LEN_1K * 4;

			OPF_Bin2Str(ex->value->data+(ex->value->length-1),1,szTmp,&ulOutLen);
			
			strcat(szCertKeyUsage, szTmp);
			strcat(szCertKeyUsage, ")");
		}
		return 0;
	}

	return 0;	//没有找到扩展项，证明签名验证都可以做
}

//证书目的
int GetCertPurposes(X509 *x, char *szCertPurpose, int *pnCertPurposeLen)
{
	EXTENDED_KEY_USAGE *extusage = NULL;	
	int i;

	if(NULL == szCertPurpose)
	{
		return -1;
	}

	if((extusage=(EXTENDED_KEY_USAGE *)X509_get_ext_d2i(x, NID_ext_key_usage, NULL, NULL))) {
		x->ex_flags |= EXFLAG_XKUSAGE;
		for(i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
			switch(OBJ_obj2nid(sk_ASN1_OBJECT_value(extusage,i))) {
			case NID_server_auth:
				x->ex_xkusage |= XKU_SSL_SERVER;
				strcat(szCertPurpose, "Ensures the identity of a remote compute.\n");
				break;

			case NID_client_auth:
				x->ex_xkusage |= XKU_SSL_CLIENT;
				strcat(szCertPurpose, "Proves your identity to a remote computer.\n");
				break;

			case NID_email_protect:
				x->ex_xkusage |= XKU_SMIME;
				strcat(szCertPurpose, "Protects e-mail messages.\n");
				break;

			case NID_code_sign:
				x->ex_xkusage |= XKU_CODE_SIGN;
				strcat(szCertPurpose, "Ensures software came from software publisher.\n");
				strcat(szCertPurpose, "Protects software from alteration after publication.\n");
				break;

			case NID_ms_sgc:
			case NID_ns_sgc:
				x->ex_xkusage |= XKU_SGC;
				break;

			case NID_OCSP_sign:
				x->ex_xkusage |= XKU_OCSP_SIGN;				
				break;

			case NID_time_stamp:
				x->ex_xkusage |= XKU_TIMESTAMP;
				strcat(szCertPurpose, "Allows data to be signed with the current time\n");
				break;

			case NID_dvcs:
				x->ex_xkusage |= XKU_DVCS;
				break;
			}
		}
		sk_ASN1_OBJECT_pop_free(extusage, ASN1_OBJECT_free);
	}

	if(0 == strlen(szCertPurpose))
	{
		strcpy(szCertPurpose, "All issuance policies.\n");
		strcat(szCertPurpose, "All application policies.\n");
	}
	return 0;
}

int COMMON_API OpenSSL_PraseCertInfo(int iNameID, int iSubNameID, char *pszGB, int* piLen)
{
	unsigned int ulRet = 0;
	char data_value[BUFFER_LEN_1K * 4] = {0};
	unsigned long data_len = 0;

	int i = 0, j = 0;

	if (!x509)
	{
		ulRet = -1; // not init
		goto err;
	}

	//获得证书的主题、颁发者、序列号、有效期
	switch(iNameID)
	{
	case ECERT_INFO_NAME:		//主题项
		{
			if( (NID_COMMONNAME != iSubNameID) 
				&& (NID_COUNTRYNAME != iSubNameID) 
				&& (NID_LOCALITYNAME != iSubNameID) 
				&& (NID_STATEORPROVINCENAME != iSubNameID) 
				&& (NID_ORGANIZATIONNAME != iSubNameID)
				&& (NID_ORGANIZATIONALUNITNAME != iSubNameID) 
				&& (NID_PKCS9_EMAILADDRESS != iSubNameID) 
				&& (-1 != iSubNameID)			//表示此参数不起作用
				)
			{				
				ulRet = -1;
				goto err;
			}

			X509_NAME * pX509_Name_Subject = X509_get_subject_name(x509);	

			int pos = -1; 

			if (iSubNameID == NID_COMMONNAME)
			{
				int pos = -1;

				pos = X509_NAME_get_index_by_NID(pX509_Name_Subject, NID_commonName, pos);  

				if (-1 == pos)
				{
					pos = X509_NAME_entry_count(pX509_Name_Subject)-1;
				}

				ASN1_STRING * d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(pX509_Name_Subject, pos)); 

				if (d)
				{
					strcpy(data_value,(char *)d->data); 
					data_len = strlen(data_value);
				}
			}
			else if (-1 != iSubNameID)
			{
				pos = X509_NAME_get_index_by_NID(pX509_Name_Subject, nids[iSubNameID].key, pos);  
				
				if (pos == -1)
				{
					data_len = 0;
				}
				else
				{
					ASN1_STRING * d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(pX509_Name_Subject, pos));

					sprintf(data_value + data_len,"%s = %s\n", nids[i].name, d->data);  
					data_len = strlen(data_value);
				}
			}
			else
			{
				j = X509_NAME_entry_count(pX509_Name_Subject);  

				for (i = 0; i < ENTRY_COUNT; i++) {  
					pos = -1;  
					for (;;) 
					{
						pos = X509_NAME_get_index_by_NID(pX509_Name_Subject, nids[i].key, pos);  

						if (pos == -1)
						{
							break;
						}

						ASN1_STRING * d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(pX509_Name_Subject, pos)); 
						sprintf(data_value + data_len,"%s = %s\n", nids[i].name, d->data);  
						data_len = strlen(data_value);
					}
				}
			}
		}
		break;

	case ECERT_INFO_ISSUER:		//主题项
		{
			if( (NID_COMMONNAME != iSubNameID) 
				&& (NID_COUNTRYNAME != iSubNameID) 
				&& (NID_LOCALITYNAME != iSubNameID) 
				&& (NID_STATEORPROVINCENAME != iSubNameID) 
				&& (NID_ORGANIZATIONNAME != iSubNameID)
				&& (NID_ORGANIZATIONALUNITNAME != iSubNameID) 
				&& (NID_PKCS9_EMAILADDRESS != iSubNameID) 
				&& (-1 != iSubNameID)			//表示此参数不起作用
				)
			{				
				return -1;
			}

			X509_NAME * pX509_Name_Subject = X509_get_issuer_name(x509);

			int pos = -1; 

			if (iSubNameID == NID_COMMONNAME)
			{
				int pos = -1;

				pos = X509_NAME_get_index_by_NID(pX509_Name_Subject, NID_commonName, pos);  

				if (-1 == pos)
				{
					pos = X509_NAME_entry_count(pX509_Name_Subject)-1;
				}

				ASN1_STRING * d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(pX509_Name_Subject, pos)); 

				if (d)
				{
					strcpy(data_value,(char *)d->data); 
					data_len = strlen(data_value);
				}
			}
			else if (-1 != iSubNameID)
			{
				pos = X509_NAME_get_index_by_NID(pX509_Name_Subject, nids[iSubNameID].key, pos);  

				if (pos == -1)
				{
					ulRet = -1;
					goto err;
				}
				else
				{
					ASN1_STRING * d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(pX509_Name_Subject, pos));

					sprintf(data_value + data_len,"%s = %s\n", nids[i].name, d->data);  
					data_len = strlen(data_value);
				}
			}
			else
			{
				j = X509_NAME_entry_count(pX509_Name_Subject);  

				for (i = 0; i < ENTRY_COUNT; i++) {  
					pos = -1;  
					for (;;) 
					{
						pos = X509_NAME_get_index_by_NID(pX509_Name_Subject, nids[i].key, pos);  

						if (pos == -1)
						{
							break;
						}

						ASN1_STRING * d = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(pX509_Name_Subject, pos)); 
						sprintf(data_value + data_len,"%s = %s\n", nids[i].name, d->data);  
						data_len = strlen(data_value);
					}
				}
			}
			return 0;
		}
		break;

	case ECERT_INFO_SN:		//证书序列号
		{
			ASN1_INTEGER *serialNumber = NULL;

			serialNumber = X509_get_serialNumber(x509);						
			if(NULL == serialNumber)
			{
				ulRet = -1;
				goto err;;
			}

			int iLen = serialNumber->length;
			unsigned char * pbTemp = new unsigned char[iLen+1];
			memset(pbTemp, 0, iLen+1);
			unsigned char * p = pbTemp;

			iLen = i2c_ASN1_INTEGER(serialNumber, &p);

			for(i=0; i<iLen; i++)
			{
				sprintf(&data_value[i*3], "%02X ", pbTemp[i]);
			}

			if(pbTemp)
			{
				delete[] pbTemp;
			}

			data_len = iLen*3;

			ulRet = 0;
		}
		break;	
	case ECERT_INFO_NOTBEFORE:		//before时间
		{
			ASN1_TIME *pasn1Time = NULL;	

			//得到证书时间
			pasn1Time = X509_get_notBefore(x509);
			if(NULL == pasn1Time)
			{
				ulRet = -1;
				goto err;
			}

			//时间转化
			int err;

			time_t timeTmp = ASN1_TIME_get(pasn1Time,&err);

			if(0 == err)
			{
				string strTimeTmp;

				API_TimeToStringEX(strTimeTmp,timeTmp);

				sprintf(data_value, "%s",strTimeTmp.c_str());

				data_len = strlen(strTimeTmp.c_str());
			}
			else
			{
				ulRet  = -1;
				goto err;
			}
		}
		break;
	case ECERT_INFO_NOTAFTER:		//after时间
		{
			ASN1_TIME *pasn1Time = NULL;
			pasn1Time = X509_get_notAfter(x509);
			if(NULL == pasn1Time)
			{
				ulRet = -1;
				goto err;
			}

			//时间转化
			int err;

			time_t timeTmp = ASN1_TIME_get(pasn1Time,&err);

			if(0 == err)
			{
				string strTimeTmp;

				API_TimeToStringEX(strTimeTmp,timeTmp);

				sprintf(data_value, "%s",strTimeTmp.c_str());

				data_len = strlen(strTimeTmp.c_str());
			}
			else
			{
				ulRet  = -1;
				goto err;
			}
		}
		break;
	case ECERT_INFO_VERSION:	
		{			
			int iLen = X509_get_version(x509);
			iLen++;
			sprintf(data_value, "V%d", iLen);

			data_len = strlen(data_value);
			ulRet = 0;
		}
		break;
	case ECERT_INFO_PUBKEY:		//Publickey
		{			
			ASN1_BIT_STRING *pubkey = NULL;

			pubkey = X509_get0_pubkey_bitstr(x509);
			
			if(NULL == pubkey)
			{
				ulRet  = -1;
				goto err;
			}				

			for(i=0; i<pubkey->length; i++)
			{
				sprintf(&data_value[i*3], "%02X ", pubkey->data[i]);
			}				

			data_len = (pubkey->length)*3;

			ulRet  = 0;
		}
		break;

	case ECERT_INFO_SIG_ALG:
		{
			int iLen = 256;
			unsigned char * pbTemp = new unsigned char[iLen+1];
			memset(pbTemp, 0, iLen+1);
			iLen = OBJ_obj2txt((char*)pbTemp, iLen, x509->sig_alg->algorithm, 0);
			data_len = iLen;
			
			//1.2.156.10197.1.501
			if(0 == memicmp(pbTemp, "1.2.156.10197.1.501", strlen("1.2.156.10197.1.501")))
			{	
				strcpy(data_value, "SM3SM2");
			}
			else
			{
				strcpy(data_value, (char*)pbTemp);
			}
			
			if(pbTemp)
			{
				delete[] pbTemp;
			}

			data_len = strlen(data_value);

			ulRet = 0;
		}
		break;

	case ECERT_INFO_KEYUSAGE:
		{
			int data_len_int = BUFFER_LEN_1K * 4;


			ulRet = GetCertKeyUsage(x509, data_value, &data_len_int);

			data_len = data_len_int;
		}
		break;
	case ECERT_INFO_PURPOSE:
		{
			int data_len_int = BUFFER_LEN_1K * 4;

			ulRet = GetCertPurposes(x509, data_value, &data_len_int);

			data_len = data_len_int;
		}
		break;
	}
err:

	if (ulRet)
	{
		// err;
	}
	else
	{
		if (data_len + 1 <= *piLen)
		{
			*piLen = data_len + 1;

			strcpy(pszGB,data_value);
		}
		else
		{
			*piLen = data_len + 1;
		}
	}

	return ulRet;
}


int COMMON_API OpenSSL_PraseCertFinalize()
{
	//清除以前cert
	if(x509)
	{
		X509_free(x509);
		x509 = NULL;
	}

	return 0;
}