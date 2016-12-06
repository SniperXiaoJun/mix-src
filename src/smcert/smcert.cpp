#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <locale.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include "smcert.h"

#pragma comment(lib, "libeay32.lib")

X509 *g_MyCert = NULL;


//-------------------------------------------------------------------------------------------------
int mypint( const char ** s,
		   
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

time_t ASN1_TIME_get ( ASN1_TIME * a,
					  
					  int *err
					  
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
	
	time_t i, year, isleap, offset;
	
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
	
	s = (const char*)a->data; // Data should be always null terminated
	
	if (s == NULL || s[a->length] != '\0') {
		
		*err = 1;
		
		return 0;
		
	}
	
	
	*err = 0;
	
	if (generalized) {
		
		t.tm_year = mypint(&s, 4, 0, 9999, err) - 1900;
		
	} else {
		
		t.tm_year = mypint(&s, 2, 0, 99, err);
		
		if (t.tm_year < 50) t.tm_year += 100;
		
	}
	
	t.tm_mon = mypint(&s, 2, 1, 12, err) - 1;
	
	t.tm_mday = mypint(&s, 2, 1, 31, err);
	
	// NOTE: It's not yet clear, if this implementation is 100% correct
	
	// for GeneralizedTime... but at least misinterpretation is
	
	// impossible --- we just throw an exception
	
	t.tm_hour = mypint(&s, 2, 0, 23, err);
	
	t.tm_min = mypint(&s, 2, 0, 59, err);
	
	if (*s >= '0' && *s <= '9') {
		
		t.tm_sec = mypint(&s, 2, 0, 59, err);
		
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
		
		offset = mypint(&s, 2, 0, 12, err);
		
		offset *= 60;
		
		offset += mypint(&s, 2, 0, 59, err);
		
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
	
	if ( sizeof (time_t) == 4) {
		
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
		
		if ( sizeof (time_t) > 4) {
			
			for (i = 1900; i >= year; i -= 100) {
				
				if (i % 400 == 0) continue ;
				
				retval += 86400;
				
			}
			
		}
		
		if (retval >= 0) *err = 2;
		
	} else {
		
		retval += ((year - 1970 + 1) / 4) * 86400;
		
		if ( sizeof (time_t) > 4) {
			
			for (i = 2100; i < year; i += 100) {
				
				// The following condition is the reason to
				
				// start with 2100 instead of 2000
				
				if (i % 400 == 0) continue ;
				
				retval -= 86400;
				
			}
			
		}
		
		if (retval < 0) *err = 2;
		
	}
	
	
	if (*err) retval = 0;
	
	return retval;
	
}

// Convert the hex data to the hex ASCII string in characters, the length of the hex ASCII string in characters is 2*ulHexLen.
// For example: "\x01\x23\x45\x67\x89\xAB\xCD\xEF" --> "0123456789ABCDEF".
// Parameters:
// IN unsigned char *pbHex: Supplies the hex data.
// IN unsigned long ulHexLen: Supplies the length of pbHex.
// OUT char *pStr: Receives the converted hex ASCII string, supposed the pointer is legal and the buffer is big enough.
//					The length of pStr in characters is 2*ulHexLen.
unsigned long HexToStrA
(
	unsigned char *pbHex,
	unsigned long ulHexLen,
	char *pStr
	)
{
	unsigned long i;
	unsigned char ucHigh,ucLow;
	
	if(ulHexLen==0)
		return 0;
	if(!pbHex || !pStr)
		return WT_ERR_UNKNOWNERR;
	for(i=0;i<ulHexLen;i++)
	{
		ucHigh=(pbHex[i]&0xf0)>>4;		// the high half byte
		ucLow=pbHex[i]&0x0f;			// the low half byte
		
		if(ucHigh<=9)		// 0-9
			pStr[2*i]=ucHigh+0x30;
		else							// A-F
			pStr[2*i]=ucHigh+0x37;
		
		if(ucLow<=9)
			pStr[2*i+1]=ucLow+0x30;
		else
			pStr[2*i+1]=ucLow+0x37;
	}
	return 0;
}

void TimetToSystemTime( time_t t, LPSYSTEMTIME pst )
{
	FILETIME ft;
	LONGLONG ll = Int32x32To64(t, 10000000) + 116444736000000000;
	ft.dwLowDateTime = (DWORD) ll;
	ft.dwHighDateTime = (DWORD)(ll >> 32);
	FileTimeToSystemTime( &ft, pst );
}

//#define USE_NSPR
#ifdef USE_NSPR
#include "secder.h"

void ASN1UTCTime2String(ASN1_TIME *pasn1Time, char *szTime, int *pnTimeLen)
{
	PRTime pr_time = 0;
	char *ptr_time = NULL;

	DER_AsciiToTime(&pr_time,(char *)pasn1Time->data);

	// "%m/%d/%y",
	// "%H:%M:%S", 

	ptr_time = CERT_UTCTime2FormattedAscii(pr_time,"%Y-%m-%d %H:%M:%S");

	strcpy(szTime,ptr_time);
	*pnTimeLen = strlen(ptr_time);
}
#else
	

void time_t_to_c_str(time_t time,char *szTime, int *pnTimeLen)
{
	struct tm *p;

	p = localtime(&time);

	p->tm_year = p->tm_year + 1900;
	p->tm_mon = p->tm_mon + 1;

	sprintf(szTime,"%04d-%02d-%02d %02d:%02d:%02d",
		p->tm_year, p->tm_mon, p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);

	*pnTimeLen = strlen(szTime);
}

void ASN1UTCTime2String(ASN1_TIME *pasn1Time, char *szTime, int *pnTimeLen)
{
	int			ret = 0;
	
	time_t		timet;
	SYSTEMTIME	pst;
	SYSTEMTIME	pCurrent;

	//中国时区的信息  
	TIME_ZONE_INFORMATION DEFAULT_TIME_ZONE_INFORMATION = {-480};  

	*pnTimeLen = 0;

	//1.将ASN1编码的字符串（UTC时间） 转化为time_t
	timet = ASN1_TIME_get(pasn1Time, &ret);
	if(0 != ret)
	{
		return;
	}

#if 0
	// 该结果有问题 只能到2038年
	//2.将time_t转化为SYSTEMTIME
	TimetToSystemTime(timet, &pst);

	//3.中国时区转化：SYSTEMTIME 转化为 SYSTEMTIME
	//
	//将UTC时间转换为中国时区的本地时间  
	SystemTimeToTzSpecificLocalTime(&DEFAULT_TIME_ZONE_INFORMATION, &pst, &pCurrent);

	*pnTimeLen = 19;	//等于"%02d-%02d-%02d %02d:%02d:%02d"的长度
	if(szTime)
	{
		sprintf(szTime, 
				"%04d-%02d-%02d %02d:%02d:%02d", 
				pCurrent.wYear,
				pCurrent.wMonth,
				pCurrent.wDay, 
				pCurrent.wHour, 
				pCurrent.wMinute, 
				pCurrent.wSecond);
		*pnTimeLen = strlen(szTime);
	}
#else
	time_t_to_c_str(timet,szTime,pnTimeLen);
#endif
}
	
#endif



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
			HexToStrA(ex->value->data+(ex->value->length-1), 1, szTmp);
			strcat(szCertKeyUsage, szTmp);
			strcat(szCertKeyUsage, ")");
		}
		return WT_OK;
	}

	return WT_OK;	//没有找到扩展项，证明签名验证都可以做
}

//证书目的
int GetCertPurposes(X509 *x, char *szCertPurpose, int *pnCertPurposeLen)
{
	EXTENDED_KEY_USAGE *extusage = NULL;	
	int i;
	
	if(NULL == szCertPurpose)
		return WT_ERR_BUFFER_TOO_SMALL;

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
	return WT_OK;
}
//-------------------------------------------------------------------------------------------------

//设置证书,支持PEM以及DER格式
int SetMyCert(unsigned char *pbMyCert, unsigned long ulCertLen)
{	
	BIO *biocert = NULL;
	
	//清除以前cert
	if(g_MyCert)
	{
		X509_free(g_MyCert);
		g_MyCert = NULL;
	}

	//读取Cert，支持PEM以及DER格式
	biocert = BIO_new_mem_buf(pbMyCert, ulCertLen);
	if(NULL == biocert)
	{		
		return WT_ERR_MEMORY;
	}

	g_MyCert = PEM_read_bio_X509(biocert,NULL,NULL,NULL);	//pem
	if(g_MyCert == NULL)
	{
		BIO_reset(biocert);
		
		g_MyCert = d2i_X509_bio(biocert, NULL);	//der
		if(g_MyCert == NULL)
		{			
			return WT_ERR_FILE;	
		}
	}	
	if(biocert)
	{
		BIO_free(biocert);
	}

	return WT_OK;
}

#if 0
//根据名称获得nid
int GetNIDByName(char *szName)
{	
	int iNid = -1;
	INTSTR_MAP::iterator itor;
	string a;

	//根据名称查找对应的NID
	for(itor = m_Map.begin(); itor!=m_Map.end(); itor++)
	{		
		iNid = itor->first;
		a = itor->second.data();
#ifdef	WIN32
		if(0 == stricmp(itor->second.data(), szName))
#else
		if(0 == strcasecmp(itor->second.data(), szName))
#endif
		{
			iNid = itor->first;
			a = itor->second.data();
			return iNid;			
		}
	}
	
	return iNid;
}
#endif

int HexToTen(char *hex)
{
	int len = 4;	//strlen(hex);
	int nCount = 0;
	int i,nTemp;
	
	for(i=0; i<len; i++)
	{
		if((hex[i]>=0x30) && (hex[i]<0x3A))//0~9
			nTemp = hex[i]-0x30;
		if((hex[i]>='a') && (hex[i]<'g'))//a~f
			nTemp = hex[i]-0x64 + 9;
		if((hex[i]>='A') && (hex[i]<'G'))//A~F
			nTemp = hex[i]-0x40 + 9;
		nCount = nCount + (nTemp<<((len-i-1)*4));
	}

	return nCount;
}

static int UniToUTF8(wchar_t *strUnicode,char *szUtf8)
{
	//MessageBox(strUnicode);
	int ilen = WideCharToMultiByte(CP_UTF8, 0, (wchar_t*)strUnicode, -1, NULL, 0, NULL, NULL); 
	char *szUtf8Temp=new char[ilen + 1];
	memset(szUtf8Temp, 0, ilen +1); 
	WideCharToMultiByte (CP_UTF8, 0, (wchar_t*)strUnicode, -1, szUtf8Temp, ilen, NULL,NULL); 
	//size_t a = strlen(szUtf8Temp);
	sprintf(szUtf8, "%s", szUtf8Temp);// 
	delete[] szUtf8Temp; 
	return ilen;
}

//字符串转化成ASC,字符串支持unicode、utf-8
void StringToAscii(char *pszBuf, char *pszGB)
{	
	char	szTempBuf[4] = {0};
	char	*pszDest = NULL;	
	char	*p = NULL;
	char	szHex[5] = {0};
	wchar_t pwcStr[2] = {0};
	unsigned int	uiUlocal=0;
	int	i;
	
	//开始区分字符
	p = pszBuf;	
	for(i=0; ; i++)
	{
        pszDest = strstr(p, "\\U");
		if(pszDest == NULL)
		{			
			//strncpy(pszGB,  p, strlen(p));
			strncat(pszGB,  p, strlen(p));
			break;
		}
		uiUlocal = pszDest - p + 1;
		//英文		
		strncat(pszGB,  p, uiUlocal-1);
		//中文
		memset(szHex, 0, 5);
		strncpy(szHex, &p[uiUlocal+1], 4);		
		pwcStr[0] = HexToTen(szHex);
		//中文宽字符转换
		//if(wcstombs( szTempBuf, pwcStr, 2 ) != -1) // 该函数在中文系统无问题，在英文系统有问题
		//{
		//	strncat(pszGB, szTempBuf,2);
		//}
		//else 
		if(UniToUTF8(pwcStr,szTempBuf)) // 英文中文系统处理
		{
			strncat(pszGB, szTempBuf,strlen(szTempBuf));
		}

		p = p+uiUlocal+1+4;
	}
}

//根据nid获得证书信息，nid = -1时返回全部DN数据
int GetInfoByNameID(X509_NAME *certname, int inID, char *pszOut, int *piOutLen)
{
	X509_NAME_ENTRY	*ne;
	ASN1_STRING		*asn1_str = NULL;
	BUF_MEM			*bptr = NULL;
	BIO				*mem = NULL;
	const char		*s = NULL;
	char	*p = NULL;	
	char	tmp_buf[80] = {0};		
	char	*pszBuf = NULL;	
	int		iLen;
	int		i, n, iTempLen;
	char	*pszTempBuf = NULL;

	if(NULL == certname)
	{		
		return NULL;
	}
	if(NULL != pszOut)
	{
		pszOut[0] = '\0';
	}

	*piOutLen = 0;

	//设置环境
	setlocale(LC_CTYPE, "");
		
	// 获得所有的对象

	for(i=sk_X509_NAME_ENTRY_num(certname->entries)-1; i>=0; i--)
	{
		ne = sk_X509_NAME_ENTRY_value(certname->entries, i);
		n = OBJ_obj2nid(ne->object);
		if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL))
		{
			i2t_ASN1_OBJECT(tmp_buf, sizeof(tmp_buf), ne->object);
			s = tmp_buf;
		}

		//如果传入inID!=-1表示只取得inID对应的数据，否则全部取出
		if( (-1 != inID) && (inID != n))
		{		
			continue;
		}

		//标志头的长度
		iTempLen = strlen(s);
		//Get ASN1
		asn1_str = X509_NAME_ENTRY_get_data(ne);		
		//BIO 	
		mem = BIO_new(BIO_s_mem());
		BIO_set_close(mem, BIO_CLOSE); 
		ASN1_STRING_print_ex(mem, asn1_str, ASN1_STRFLGS_ESC_QUOTE );	
		BIO_get_mem_ptr(mem, &bptr);		
		//编码前的长度
		iLen = bptr->length;		
		pszBuf = new char[iLen+1];
		memset(pszBuf, 0, iLen+1);		
		memcpy(pszBuf, bptr->data, iLen);
		if(mem != NULL)
		{
			BIO_free(mem);
			mem = NULL;
		}		

		//获得对象内容 长度为转化的长度iLen + s字符串的长度iTempLen + "//" + "=" +1 
		pszTempBuf = new char[iLen+iTempLen+3];
		memset(pszTempBuf, 0, iLen+iTempLen+3);	

#if 0
		//目前代码,最后有分隔符'/'
		p = pszTempBuf;
		// *(p++)='/';
		memcpy(p, s, iTempLen);
		p+=iTempLen;
		*(p++)='=';

		//转化编码
		StringToAscii(pszBuf, p);

		p = p+strlen(p);

		//如果传入inID==-1表示取得inID对应的全部数据
		if(-1 == inID)
			*(p++)='/';

		*piOutLen = *piOutLen + strlen(pszTempBuf);
#else	
		if(0 == pszOut[0])
		{
			p = pszTempBuf;
			memcpy(p, s, iTempLen);
			p+=iTempLen;
			*(p++)='=';
		}
		else
		{
			//以前代码,先有分隔符'/'
			p = pszTempBuf;
			*(p++)='/';
			memcpy(p, s, iTempLen);
			p+=iTempLen;
			*(p++)='=';
		}

		//转化编码
		StringToAscii(pszBuf, p);
		*piOutLen = *piOutLen + strlen(pszTempBuf);
#endif	

		//如果返回数据没有分配地址，返回长度
		if(NULL != pszOut)
		{			
			//最终全部转化为UTF-8

			strcat(pszOut, pszTempBuf);
		}
		if(pszBuf)
		{
			delete[] pszBuf;
		}
		if(pszTempBuf)
		{
			delete[] pszTempBuf;
		}		
	}

	if (inID == NID_COMMONNAME)
	{
		if (0 == pszOut[0])
		{
			i=sk_X509_NAME_ENTRY_num(certname->entries)-1;

			ne = sk_X509_NAME_ENTRY_value(certname->entries, i);
			n = OBJ_obj2nid(ne->object);
			if ((n == NID_undef) || ((s = OBJ_nid2sn(n)) == NULL))
			{
				i2t_ASN1_OBJECT(tmp_buf, sizeof(tmp_buf), ne->object);
				s = tmp_buf;
			}

			//标志头的长度
			iTempLen = strlen(s);
			//Get ASN1
			asn1_str = X509_NAME_ENTRY_get_data(ne);		
			//BIO 	
			mem = BIO_new(BIO_s_mem());
			BIO_set_close(mem, BIO_CLOSE); 
			ASN1_STRING_print_ex(mem, asn1_str, ASN1_STRFLGS_ESC_QUOTE );	
			BIO_get_mem_ptr(mem, &bptr);		
			//编码前的长度
			iLen = bptr->length;		
			pszBuf = new char[iLen+1];
			memset(pszBuf, 0, iLen+1);		
			memcpy(pszBuf, bptr->data, iLen);
			if(mem != NULL)
			{
				BIO_free(mem);
				mem = NULL;
			}

			//获得对象内容 长度为转化的长度iLen + s字符串的长度iTempLen + "//" + "=" +1 
			pszTempBuf = new char[iLen+iTempLen+3];
			memset(pszTempBuf, 0, iLen+iTempLen+3);	

			if(0 == pszOut[0])
			{
				p = pszTempBuf;
				memcpy(p, s, iTempLen);
				p+=iTempLen;
				*(p++)='=';
			}
			else
			{
				//以前代码,先有分隔符'/'
				p = pszTempBuf;
				*(p++)='/';
				memcpy(p, s, iTempLen);
				p+=iTempLen;
				*(p++)='=';
			}

			//转化编码
			StringToAscii(pszBuf, p);
			*piOutLen = *piOutLen + strlen(pszTempBuf);

			//如果返回数据没有分配地址，返回长度
			if(NULL != pszOut)
			{			
				//最终全部转化为UTF-8

				strcat(pszOut, pszTempBuf);
			}
			if(pszBuf)
			{
				delete[] pszBuf;
			}
			if(pszTempBuf)
			{
				delete[] pszTempBuf;
			}	
		}
		else
		{

		}
	}

	return *piOutLen;
}

//根据名称获取证书信息
int GetCertInfo(char *szNIDName, char *szSubNIDName, char *pszGB, int* piLen)
{
	X509_NAME *certname = NULL;
	int			i;
	int			iLen;		
	int			ret = -1;
	int			iGBLen;
	int			iNameID = -1;
	unsigned char *pbTemp = NULL;
	unsigned char *p = NULL;

	if(NULL == g_MyCert)
	{
		return ret;
	}

	//根据名称获得NID
//	iNameID = GetNIDByName(szNIDName);
	if(-1 == iNameID)
	{
		//没有找到名称,默认返回DN
		iNameID = CERT_SUBJECT_DN;
	}
	//获得证书的主题、颁发者、序列号、有效期
	switch(iNameID)
	{
	case CERT_SUBJECT_DN:		//主题项
		{
			iNameID = -1;
			if(NULL != szSubNIDName)
			{
//				iNameID = GetNIDByName(szSubNIDName);
			}
			
			certname = X509_get_subject_name(g_MyCert);		
			ret = GetInfoByNameID(certname, iNameID, pszGB, &iGBLen);
#if 0
			//debug test
			X509_NAME *certname = X509_get_subject_name(g_MyCert);
			char buf[256];
			memset(buf, 0, 256);
			ret = X509_NAME_get_text_by_NID(certname, 13, buf, 256);
			if((int)ret<0)
			{			
				return ret;
			}
			if(pszGB)
				strcpy(pszGB, buf);
#endif
			*piLen = ret;
			return 0;
		}
		break;
	case CERT_ISSUER_DN:		//颁发者
		{
			iNameID = -1;
			if(NULL != szSubNIDName)
			{
//				iNameID = GetNIDByName(szSubNIDName);
			}
			certname = X509_get_issuer_name(g_MyCert);			

			ret = GetInfoByNameID(certname, iNameID, pszGB,  &iGBLen);
			if((int)ret<0)
			{			
				return ret;
			}
			*piLen = ret;
			return 0;
		}
		break;
	case CERT_SERIALNUMBER:		//证书序列号
		{
			ASN1_INTEGER *serialNumber = NULL;
			
			serialNumber = X509_get_serialNumber(g_MyCert);						
			if(NULL == serialNumber)
			{
				ret = -1;
				return ret;
			}

			iLen = serialNumber->length;
			pbTemp = new unsigned char[iLen+1];
			memset(pbTemp, 0, iLen+1);
			p = pbTemp;
			iLen = i2c_ASN1_INTEGER(serialNumber, &p);
			if(NULL != pszGB)
			{				
				for(i=0; i<iLen; i++)
				{
					sprintf(&pszGB[i*2], "%02x", pbTemp[i]);
				}				
			}
			if(pbTemp)
			{
				delete[] pbTemp;
			}
			*piLen = iLen*2;
			ret = 0;
		}
		break;		
	
	case CERT_NOTBEFORE:		//before时间
		{
			ASN1_TIME *pasn1Time = NULL;
			pasn1Time = X509_get_notBefore(g_MyCert);
			if(NULL == pasn1Time)
			{
				ret = -1;
				return ret;
			}
			if(NULL != pszGB)
			{
				memcpy(pszGB, pasn1Time->data, pasn1Time->length);
			}
			*piLen = pasn1Time->length;			
			ret = 0;
		}
		break;
	case CERT_NOTAFTER:		//after时间
		{
			ASN1_TIME *pasn1Time = NULL;
			pasn1Time = X509_get_notAfter(g_MyCert);
			if(NULL == pasn1Time)
			{
				ret = -1;
				return ret;
			}
			if(NULL != pszGB)
			{
				memcpy(pszGB, pasn1Time->data, pasn1Time->length);
			}
			*piLen = pasn1Time->length;
			ret = 0;
		}
		break;
	case CERT_SUBJECTPUBLICKEYINFO:		//Publickey
		{
			EVP_PKEY *pkey = NULL;
			pkey = X509_get_pubkey(g_MyCert);
			if(NULL == pkey)
			{
				ret = -1;
				return ret;
			}
					
			iLen = i2d_PublicKey(pkey, &pbTemp);
			if(NULL != pszGB)
			{				
				for(i=0; i<iLen; i++)
				{
					sprintf(&pszGB[i*2], "%02x", pbTemp[i]);
				}				
			}	
			
			*piLen = iLen*2;
			ret = 0;
		}
		break;
	case CERT_VERSION:	
		{			
			iLen = X509_get_version(g_MyCert);
			iLen++;
			*piLen = 1;
			if(NULL != pszGB)
			{	
#ifdef	WIN32
				itoa(iLen, pszGB, 10);
#else
				sprintf(pszGB, "%d", iLen);
#endif
			}
			ret = 0;
		}
		break;
	case CERT_SIGNATUREALGORITHM:
		{
			iLen = 256;
			pbTemp = new unsigned char[iLen+1];
			memset(pbTemp, 0, iLen+1);
			iLen = OBJ_obj2txt((char*)pbTemp, iLen, g_MyCert->sig_alg->algorithm, 0);
			*piLen = iLen;
			if(NULL != pszGB)
			{	
				strcpy(pszGB, (char*)pbTemp);
			}
			if(pbTemp)
			{
				delete[] pbTemp;
			}
			ret = 0;
		}
		break;

	default:
		break;
	}

	return ret;
}


//根据ID获取证书信息
int GetCertInfoFromID(int iNameID, int iSubNameID, char *pszGB, int* piLen)
{
	X509_NAME	*certname = NULL;
	int			i;
	int			iLen;		
	int			ret = -1;
	int			iGBLen;
	
	unsigned char *pbTemp = NULL;
	unsigned char *p = NULL;

	if(NULL == g_MyCert)
	{
		return ret;
	}
	
	//获得证书的主题、颁发者、序列号、有效期
	switch(iNameID)
	{
	case CERT_SUBJECT_DN:		//主题项
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
				return WT_ERR_INVALIDPARAM;
			}
			
			certname = X509_get_subject_name(g_MyCert);	

			ret = GetInfoByNameID(certname, iSubNameID, pszGB, &iGBLen);
#if 0
			//debug test
			X509_NAME *certname = X509_get_subject_name(g_MyCert);
			char buf[256];
			memset(buf, 0, 256);
			ret = X509_NAME_get_text_by_NID(certname, 13, buf, 256);
			if((int)ret<0)
			{			
				return ret;
			}
			if(pszGB)
				strcpy(pszGB, buf);
#endif
			*piLen = ret;
			return 0;
		}
		break;
	case CERT_ISSUER_DN:		//颁发者
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
				return WT_ERR_INVALIDPARAM;
			}

			certname = X509_get_issuer_name(g_MyCert);			
			if(NULL == certname)
			{
				return WT_ERR_UNKNOWNERR;
			}

			ret = GetInfoByNameID(certname, iSubNameID, pszGB,  &iGBLen);
			if((int)ret<0)
			{			
				return ret;
			}
			*piLen = ret;
			return 0;
		}
		break;
	case CERT_SERIALNUMBER:		//证书序列号
		{
			ASN1_INTEGER *serialNumber = NULL;
			
			serialNumber = X509_get_serialNumber(g_MyCert);						
			if(NULL == serialNumber)
			{
				ret = -1;
				return ret;
			}

			iLen = serialNumber->length;
			pbTemp = new unsigned char[iLen+1];
			memset(pbTemp, 0, iLen+1);
			p = pbTemp;
			iLen = i2c_ASN1_INTEGER(serialNumber, &p);
			if(NULL != pszGB)
			{				
				for(i=0; i<iLen; i++)
				{
					sprintf(&pszGB[i*3], "%02X ", pbTemp[i]);
				}				
			}
			if(pbTemp)
			{
				delete[] pbTemp;
			}
			*piLen = iLen*3;
			ret = 0;
		}
		break;		
	
	case CERT_NOTBEFORE:		//before时间
		{
			ASN1_TIME *pasn1Time = NULL;	
			
			//得到证书时间
			pasn1Time = X509_get_notBefore(g_MyCert);
			if(NULL == pasn1Time)
			{
				ret = -1;
				return ret;
			}
			
			//时间转化
			ASN1UTCTime2String(pasn1Time, pszGB, piLen);		
			
			//if(NULL != pszGB)
			//{				
			//	memcpy(pszGB, pasn1Time->data, pasn1Time->length);
			//}
			//*piLen = pasn1Time->length;			
			ret = 0;
		}
		break;
	case CERT_NOTAFTER:		//after时间
		{
			ASN1_TIME *pasn1Time = NULL;
			pasn1Time = X509_get_notAfter(g_MyCert);
			if(NULL == pasn1Time)
			{
				ret = -1;
				return ret;
			}
			
			//时间转化
			ASN1UTCTime2String(pasn1Time, pszGB, piLen);
			//if(NULL != pszGB)
			//{
			//	memcpy(pszGB, pasn1Time->data, pasn1Time->length);
			//}
			//*piLen = pasn1Time->length;
			ret = 0;
		}
		break;
	case CERT_SUBJECTPUBLICKEYINFO:		//Publickey
		{			
			ASN1_BIT_STRING *pubkey = NULL;
			
			pubkey = X509_get0_pubkey_bitstr(g_MyCert);
			if(NULL == pubkey)
			{
				ret = WT_ERR_UNKNOWNERR;
				return ret;
			}				
			
			if(NULL != pszGB)
			{				
				for(i=0; i<pubkey->length; i++)
				{
					sprintf(&pszGB[i*3], "%02X ", pubkey->data[i]);
				}				
			}	
			
			*piLen = (pubkey->length)*3;

			if(pubkey)
			{
				;//ASN1_BIT_STRING_free(pubkey);
			}

			ret = 0;
		}
		break;
	case CERT_VERSION:	
		{			
			iLen = X509_get_version(g_MyCert);
			iLen++;
			*piLen = 1;
			if(NULL != pszGB)
			{	
#ifdef	WIN32
				//itoa(iLen, pszGB, 10);
//#else
				sprintf(pszGB, "V%d", iLen);
#endif
			}
			ret = 0;
		}
		break;
	case CERT_SIGNATUREALGORITHM:
		{
			iLen = 256;
			pbTemp = new unsigned char[iLen+1];
			memset(pbTemp, 0, iLen+1);
			iLen = OBJ_obj2txt((char*)pbTemp, iLen, g_MyCert->sig_alg->algorithm, 0);
			*piLen = iLen;
			if(NULL != pszGB)
			{	
				//strcpy(pszGB, (char*)pbTemp);

				//1.2.156.10197.1.501
				if(0 == memicmp(pbTemp, "1.2.156.10197.1.501", strlen("1.2.156.10197.1.501")))
					strcpy(pszGB, "SM3SM2");
				else
					strcpy(pszGB, (char*)pbTemp);
			}
			if(pbTemp)
			{
				delete[] pbTemp;
			}
			ret = 0;
		}
		break;
	case CERT_KEYUSAGE:
		{
			ret = GetCertKeyUsage(g_MyCert, pszGB, piLen);
		}
		break;
	case CERT_PURPOSE:
		{
			ret = GetCertPurposes(g_MyCert, pszGB, piLen);
		}
		break;
	default:
		break;
	}

	return ret;
}
//-------------------------------------------------------------------------------------------------------
//功能：设置证书,支持PEM以及DER格式
//参数：pbMyCert：	证书内容
//		ulCertLen：	证书内容长度
int STDCALL WT_SetMyCert(unsigned char *pbMyCert, unsigned long ulCertLen)
{
	int nRet = 0;
	nRet = SetMyCert(pbMyCert, ulCertLen);
	return nRet;

	//int	i, j;
	//PCCERT_CONTEXT cert;
	
	/*
	//szOID_BASIC_CONSTRAINTS
	cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, pbMyCert, ulCertLen);
	if(cert)
	{
		printf("num = %d\n", cert->pCertInfo->cExtension);
		for(i=0; i<cert->pCertInfo->cExtension; i++)
		{
			printf("i = %d\n", i);
			printf("%s ", cert->pCertInfo->rgExtension[i].pszObjId);
			printf("%d \n", cert->pCertInfo->rgExtension[i].fCritical);
			for(j=0; j<cert->pCertInfo->rgExtension[i].Value.cbData; j++)
			{
				printf("%02x ", cert->pCertInfo->rgExtension[i].Value.pbData[j]);
			}
			printf("\n");
		}
		printf("\n");
	}
	*/	
}

//功能：获取证书信息
//参数：iNameID：	证书信息项，见上宏定义CERT_XXXX
//	    iSubNameID：证书信息子项，当iNameID=CERT_ISSUER_DN或CERT_SUBJECT_DN时本参数有效, 否则默认为-1, 
//					本参数有效时，可取值见上宏定义NID_XXX。
//		pszGB：		返回字符串
//		piLen：		返回字符串长度，当值pszGB为NULL时，本参数可以返回需要的缓存长度。
//备注：必须预先调用WT_SetMyCert
int STDCALL WT_GetCertInfo(int iNameID, int iSubNameID, char *pszGB, int* piLen)
{
	int nRet = 0;

	nRet = GetCertInfoFromID(iNameID, iSubNameID, pszGB, piLen);

	return nRet;
}

//功能：清除以前设置的证书
int STDCALL WT_ClearCert()
{
	//清除以前cert
	if(g_MyCert)
	{
		X509_free(g_MyCert);
		g_MyCert = NULL;
	}
	
	return 0;
}
