
#include <openssl/ec.h>
//#include <bn.h>
//#include <memory.h>

#include "gm-ecc-512.h"
#include "gm-hash-bit.h"
#include "o_all_type_def.h"

EC_GROUP *g_group512=NULL;

static char sz_p[]="C393BF6F4CDBCE9FF8ED7B89707247325A1EE68B80419E9F228B51D7B2BCEB774D5E184E0E437F38A7ACEB3933B65450E46EB984B48048E7ACCDCB6AB45E8457";
static char sz_a[]="C393BF6F4CDBCE9FF8ED7B89707247325A1EE68B80419E9F228B51D7B2BCEB774D5E184E0E437F38A7ACEB3933B65450E46EB984B48048E7ACCDCB6AB45E8454";
static char sz_b[]="0928E7617F007157EA1D14F042A365F24BDC98ECB4D4096597C7A02EFFFFFD88EDF0246C6A47A5988C9905EABC13B47AE66BD0744C5DD4F9F2731440DB32E08C";
static char sz_xG[]="4A8697E7DDD4519DF08C6E59E0602955445C4BEAE1C8CE362E6DCA4633B02066C590CB0F9D0D2337264CB3D879CF69440F2F6D5A998870F530D54642EFB910C3";
static char sz_yG[]="BD18638C707FEEBE9C3D28F9B7D4EFBAFB16E1EBBD3038B9CD039CC8C11573B2259A0F8F366B4A7C79BCA01264811779EEA9F078C7D14D9706D91FC6378BE3E4";
static char sz_order[]="C393BF6F4CDBCE9FF8ED7B89707247325A1EE68B80419E9F228B51D7B2BCEB76109E46CA4F43D7706ED82E3944F30C8374A464643A1A5860F8615690DB4198CF";

// 16进制的字符串转换成16进制数据
// 例: "0123456789ABCDEF" --> "\x01\x23\x45\x67\x89\xAB\xCD\xEF"
// IN char *pbStr: 字符串数据
// IN unsigned long ulStrLen: 字符串数据的长度, 必须是2的倍数
// OUT unsigned char *pbHex: 16进制数据, 假设该参数始终是合法指针, 且缓冲区长度足够大
static unsigned long MyStrToHexA
(
	char *pbStr,
	unsigned long ulStrLen,
	unsigned char *pbHex
)
{
	unsigned long i;
	
	if(ulStrLen==0)
		return 0;
	if(!pbHex || !pbStr || ulStrLen%2)
		return OPE_ERR_INVALID_PARAM;
	for(i=0;i<ulStrLen;i++)
	{
		if(i%2==0)
		{
			if(pbStr[i]>='0' && pbStr[i]<='9')
				pbHex[i/2]=(pbStr[i]-0x30)<<4;
			else if(pbStr[i]>='A' && pbStr[i]<='F')
				pbHex[i/2]=(pbStr[i]-0x37)<<4;
			else if(pbStr[i]>='a' && pbStr[i]<='f')
				pbHex[i/2]=(pbStr[i]-0x57)<<4;
			else
				return OPE_ERR_INVALID_PARAM;
		}
		else
		{
			if(pbStr[i]>='0' && pbStr[i]<='9')
				pbHex[i/2]|=pbStr[i]-0x30;
			else if(pbStr[i]>='A' && pbStr[i]<='F')
				pbHex[i/2]|=pbStr[i]-0x37;
			else if(pbStr[i]>='a' && pbStr[i]<='f')
				pbHex[i/2]|=pbStr[i]-0x57;
			else
				return OPE_ERR_INVALID_PARAM;
		}
	}
	return 0;
}


int tcm_gmecc512_init()
{
	BN_CTX *ctx = NULL;
	BIGNUM *p=NULL, *a=NULL, *b=NULL;
	EC_POINT *G=NULL;
	BIGNUM *x=NULL, *y=NULL, *order=NULL;

	if(g_group512)
		return 0;

	ctx = BN_CTX_new();
	if (!ctx) 
		goto err;
	BN_CTX_start(ctx);

	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	if (!p || !a || !b)
		goto err;
	
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	order = BN_CTX_get(ctx);
	if (!x || !y || !order)
		goto err;

	if (!BN_hex2bn(&p, sz_p)) 
		goto err;
	if (!BN_hex2bn(&a, sz_a))
		goto err;
	if (!BN_hex2bn(&b, sz_b))
		goto err;
	
	// applications should use EC_GROUP_new_curve_GFp so that the library gets to choose the EC_METHOD
	g_group512 = EC_GROUP_new(EC_GFp_mont_method()); 
	if (!g_group512)
		goto err;
	
	if (!EC_GROUP_set_curve_GFp(g_group512, p, a, b, ctx))
		goto err;
	
	if (!BN_hex2bn(&x, sz_xG))
		goto err;
	if (!BN_hex2bn(&y, sz_yG))
		goto err;
	
	if(!(G = EC_POINT_new(g_group512)))
		goto err;
	
	if (!EC_POINT_set_affine_coordinates_GFp(g_group512, G, x, y, ctx))
		goto err;
	
	if (!EC_POINT_is_on_curve(g_group512, G, ctx))
		goto err;
	
	if (!BN_hex2bn(&order, sz_order))
		goto err;

	if (!EC_GROUP_set_generator(g_group512, G, order, BN_value_one()))
		goto err;	

	if(G)
		EC_POINT_free(G);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return 0;
err:
	if(G)
		EC_POINT_free(G);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	
	if(g_group512)
	{
		EC_GROUP_free(g_group512);
		g_group512=NULL;
	}
	
	return -1;
}


int tcm_gmecc512_release()
{
	if(g_group512)
	{
		EC_GROUP_free(g_group512);
		g_group512=NULL;
	}

	return 0;
}


static int ParsePoint(BN_CTX *ctx, unsigned char *pointCode, unsigned int uPointCodeLen, EC_POINT *point)
{
	BIGNUM *x=NULL, *y=NULL;
	unsigned int ecLen;
	unsigned char pc;
	int y_bit;
	int nRet;

	if( (!ctx) || (!pointCode) || (0 == uPointCodeLen) || (0 == uPointCodeLen % 2 ) || (!point))
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	x = BN_new();
	if (!x )
	{
		nRet=OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	pc=pointCode[0];
	switch(pc)
	{
	case 0x02:    // 压缩, y_bit=0, 长度l+1
	case 0x03:    // 压缩, y_bit=1, 长度l+1
		ecLen=uPointCodeLen-1;
		break;
	case 0x04:    // 未压缩, 长度2l+1
	case 0x06:    // 混合, y_bit=0, 长度2l+1
	case 0x07:    // 混合, y_bit=1, 长度2l+1
		ecLen = (uPointCodeLen-1)/2;
		y = BN_new();
		if (!y )
		{
			nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
			goto err;
		}
		BN_bin2bn(pointCode+1+ecLen, ecLen, y);
		break;
	default:
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}
	BN_bin2bn(pointCode+1, ecLen, x);

	if(ecLen > GM_ECC_512_BYTES_LEN)
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	switch(pc)
	{
	case 0x02:    // 压缩, y_bit=0, 长度l+1
		if(!EC_POINT_set_compressed_coordinates_GFp(g_group512, point, x, 0, ctx))
		{
			nRet=-1;
			goto err;
		}
		break;
	case 0x03:    // 压缩, y_bit=1, 长度l+1
		if(!EC_POINT_set_compressed_coordinates_GFp(g_group512, point, x, 1, ctx))
		{
			nRet=-1;
			goto err;
		}
		break;
	case 0x04:    // 未压缩, 长度2l+1
		if(!EC_POINT_set_affine_coordinates_GFp(g_group512, point, x, y, ctx))
		{
			nRet=-1;
			goto err;
		}
		break;
	case 0x06:    // 混合, y_bit=0, 长度2l+1
	case 0x07:    // 混合, y_bit=1, 长度2l+1
		y_bit = BN_is_odd(y);

		if( y_bit != (pc-1) )
		{
			nRet=OPE_ERR_INVALID_PARAM;
			goto err;
		}
		if(!EC_POINT_set_affine_coordinates_GFp(g_group512, point, x, y, ctx))
		{
			nRet=-1;
			goto err;
		}

		break;
	default:
		nRet=OPE_ERR_INVALID_PARAM;
		goto err;
	}

	if(x)
		BN_clear_free(x);
	if(y)
		BN_clear_free(y);
	return 0;
err:
	if(x)
		BN_clear_free(x);
	if(y)
		BN_clear_free(y);
	return nRet;
}

// pointCode的内存已经分配, 且大小足够
static int PackagePoint(BN_CTX *ctx, unsigned char *pointCode, unsigned int *puPointCodeLen, EC_POINT *point, int packageType)
{
	BIGNUM *x=NULL, *y=NULL;
	unsigned char pc;
	int y_bit;
	int nRet;
	unsigned int uPointCodeLen;
	unsigned char bX[GM_ECC_512_BYTES_LEN],bY[GM_ECC_512_BYTES_LEN];
	int xLen, yLen;

	if( (!ctx) || (!pointCode) || (!puPointCodeLen) || (!point))
		goto err;

	x = BN_new();
	y = BN_new();
	if (!x || !y)
	{
		nRet=OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	if(!EC_POINT_get_affine_coordinates_GFp(g_group512, point, x, y, ctx))
	{
		nRet=-1;
		goto err;
	}

	xLen = BN_num_bytes(x);
	yLen = BN_num_bytes(y);

	// check the length of x,y 
	if( ( xLen > GM_ECC_512_BYTES_LEN) || ( yLen > GM_ECC_512_BYTES_LEN) )
	{
		nRet=OPE_ERR_INVALID_PARAM;
		goto err;
	}
	xLen = BN_bn2bin( x , bX );
	yLen = BN_bn2bin( y , bY );
	
	y_bit = BN_is_odd(y);

	switch(packageType)
	{
	case 0x02:
	case 0x03:
		if( 0 == y_bit)
			pc = 0x02;
		else
			pc = 0x03;
		uPointCodeLen = GM_ECC_512_BYTES_LEN + 1;
		memset(pointCode, 0x00, uPointCodeLen);
		pointCode[0] = pc;
		memcpy(pointCode+1+GM_ECC_512_BYTES_LEN-xLen, bX, xLen);
		break;
	case 0x04:
		pc = 0x04;
		uPointCodeLen = 2 * GM_ECC_512_BYTES_LEN + 1;
		memset(pointCode, 0x00, uPointCodeLen);
		pointCode[0] = pc;
		memcpy(pointCode+1+GM_ECC_512_BYTES_LEN-xLen, bX, xLen);
		memcpy(pointCode+1+2*GM_ECC_512_BYTES_LEN-yLen, bY, yLen);
		break;
	case 0x06:
	case 0x07:
		if( 0 == y_bit)
			pc = 0x06;
		else
			pc = 0x07;
		uPointCodeLen = 2 * GM_ECC_512_BYTES_LEN + 1;
		memset(pointCode, 0x00, uPointCodeLen);
		pointCode[0] = pc;
		memcpy(pointCode+1+GM_ECC_512_BYTES_LEN-xLen, bX, xLen);
		memcpy(pointCode+1+2*GM_ECC_512_BYTES_LEN-yLen, bY, yLen);
		break;
	default:
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	*puPointCodeLen  = uPointCodeLen;

	if(x)
		BN_clear_free(x);
	if(y)
		BN_clear_free(y);
	return 0;
err:
	if(x)
		BN_clear_free(x);
	if(y)
		BN_clear_free(y);
	return nRet;
}


int tcm_gmecc512_encrypt(unsigned char *plaintext, unsigned int uPlaintextLen, unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char *ciphertext, unsigned int *puCiphertextLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	EC_POINT *ptPubkey=NULL, *ptC1 = NULL, *tmp_point = NULL;
	BIGNUM *k = NULL, *order = NULL, *h = NULL, *x2 = NULL, *y2 = NULL;
	unsigned char b_x2y2[2*GM_ECC_512_BYTES_LEN];
	unsigned char *t = NULL, *c1 = NULL, *c2 = NULL, *c3 = NULL;
	unsigned int c1Len;
	int x2Len, y2Len;
	unsigned int i;
	gm_hash_context gm_hashCtx;
	unsigned int uCiphertextLen;

	if(!g_group512)
	{
		nRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!plaintext || 0==uPlaintextLen || !pubkey || 0==uPubkeyLen || (uPubkeyLen%2 != 1 ) || !puCiphertextLen)
	{
		nRet=OPE_ERR_INVALID_PARAM;
		goto err;
	}

	// get and check uCiphertextLen 
	uCiphertextLen =  2*GM_ECC_512_BYTES_LEN + 1 + uPlaintextLen + GM_HASH_BYTES_LEN;
	if(!ciphertext)
	{
		*puCiphertextLen = uCiphertextLen;
		nRet = 0;  // OK
		goto err;
	}
	if(*puCiphertextLen < uCiphertextLen)
	{
		*puCiphertextLen = uCiphertextLen;
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	ctx = BN_CTX_new();
	if (!ctx) 
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	BN_CTX_start(ctx);

	ptPubkey = EC_POINT_new(g_group512);
	ptC1 = EC_POINT_new(g_group512);
	tmp_point = EC_POINT_new(g_group512);
	if(!ptPubkey || !ptC1 || !tmp_point)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	// 解析获得公钥对应的点ptPubkey
	nRet = ParsePoint(ctx, pubkey, uPubkeyLen, ptPubkey);
	if( 0 != nRet)
		goto err;

	order = BN_CTX_get(ctx);
	k = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);
	if( !order || !k || !h || !x2 || !y2)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	t = OPENSSL_malloc(uPlaintextLen);
	c1 = OPENSSL_malloc(2*GM_ECC_512_BYTES_LEN+1);
	c2 = OPENSSL_malloc(uPlaintextLen);
	c3 = OPENSSL_malloc(GM_HASH_BYTES_LEN);
	if( !t || !c1 || !c2 || !c3)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	memset(t, 0x00, uPlaintextLen);
	memset(c1, 0x00, 2*GM_ECC_512_BYTES_LEN+1);
	memset(c2, 0x00, uPlaintextLen);
	memset(c3, 0x00, GM_HASH_BYTES_LEN);

	if (!EC_GROUP_get_order(g_group512, order, ctx)) 
	{
		nRet = -1;
		goto err;
	}

	// tmp_point = S = [h]PB
	if (!EC_GROUP_get_cofactor(g_group512, h, ctx)) 
	{
		nRet = -1;
		goto err;
	}
	if (!EC_POINT_mul(g_group512, tmp_point, NULL, ptPubkey, h, ctx)) 
	{
		nRet = -1;
		goto err;
	}
	if (EC_POINT_is_at_infinity(g_group512, tmp_point))
	{
		nRet = -1;
		goto err;
	}

	do{
		// generate random k
		do{
			if (!BN_rand_range(k, order)) 
			{
				nRet = -1;
				goto err;
			}
		}while (BN_is_zero(k));

		// ptC1 = [k]G
		if (!EC_POINT_mul(g_group512, ptC1, k, NULL, NULL, ctx))
		{
			nRet = -1;
			goto err;
		}

		// (x2, y2) = tmp_point = [k]PB
		if (!EC_POINT_mul(g_group512, tmp_point, NULL, ptPubkey, k, ctx)) 
		{
			nRet = -1;
			goto err;
		}
		if (!EC_POINT_get_affine_coordinates_GFp(g_group512, tmp_point, x2, y2, ctx)) 
		{
			nRet = -1;
			goto err;
		}
		// b_x2y2 = x2 || y2
		// 注意x2, y2 可能不够GM_ECC_512_BYTES_LEN字节, 按照标准, 前补0x00, 类似的地方有很多
		memset(b_x2y2, 0x00, sizeof(b_x2y2));

		x2Len = BN_num_bytes(x2);
		y2Len = BN_num_bytes(y2);
		if( (x2Len>GM_ECC_512_BYTES_LEN) || (x2Len>GM_ECC_512_BYTES_LEN) )
		{
			nRet = -1;
			goto err;
		}
		x2Len = BN_bn2bin(x2, b_x2y2 + GM_ECC_512_BYTES_LEN - x2Len);
		y2Len = BN_bn2bin(y2, b_x2y2 + 2*GM_ECC_512_BYTES_LEN - y2Len);


		// t = kdf(x2||y2, uPlaintextLen), uPlaintextLen is keylen
		nRet = gm_hash_kdf(t, uPlaintextLen, b_x2y2, 2*GM_ECC_512_BYTES_LEN, EHASH_TYPE_ZY_HASH_256);
		if( 0 != nRet)
			goto err;
		// check t 是否是全0x00
		for( i = 0; i< uPlaintextLen; i++)
		{
			if( 0x00 != t[i])
				break;
		}
	}while( i == uPlaintextLen);    // 如果t是全0x00, 循环

	// c1 = (x1,y1) 的hex编码
	c1Len = 2*GM_ECC_512_BYTES_LEN+1;
	nRet = PackagePoint(ctx, c1, &c1Len, ptC1, 0x04);
	if(0 != nRet)
		goto err;

	// c2 = plaintext (bitwise) t
	for( i = 0; i< uPlaintextLen; i++)
		c2[i] = plaintext[i] ^ t[i];

	// c3 = SM3(x2||plaintext||y2)
	memset(&gm_hashCtx,0x00,sizeof(gm_hashCtx));

	gm_hash_starts(&gm_hashCtx);
	gm_hash_update(&gm_hashCtx, b_x2y2, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, plaintext, uPlaintextLen);
	gm_hash_update(&gm_hashCtx, b_x2y2+GM_ECC_512_BYTES_LEN, GM_ECC_512_BYTES_LEN);
	gm_hash_finish(&gm_hashCtx, c3, EHASH_TYPE_ZY_HASH_256);

	// ciphertext = c1 || c2 || c3
	memcpy(ciphertext, c1, 2*GM_ECC_512_BYTES_LEN+1);
	memcpy(ciphertext + 2*GM_ECC_512_BYTES_LEN + 1, c2, uPlaintextLen);
	memcpy(ciphertext + 2*GM_ECC_512_BYTES_LEN + 1 + uPlaintextLen, c3, GM_HASH_BYTES_LEN);

	*puCiphertextLen = uCiphertextLen;

	if(t)
		OPENSSL_free(t);
	if(c1)
		OPENSSL_free(c1);
	if(c2)
		OPENSSL_free(c2);
	if(c3)
		OPENSSL_free(c3);
	
	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if (tmp_point)
		EC_POINT_free(tmp_point);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}

	return 0;
err:
	if(t)
		OPENSSL_free(t);
	if(c1)
		OPENSSL_free(c1);
	if(c2)
		OPENSSL_free(c2);
	if(c3)
		OPENSSL_free(c3);

	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if (tmp_point)
		EC_POINT_free(tmp_point);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return nRet;
}


int tcm_gmecc512_decrypt(unsigned char *ciphertext, unsigned int uCiphertextLen, unsigned char *prikey, unsigned int uPrikeyLen, unsigned char *plaintext, unsigned int *puPlaintextLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	EC_POINT *ptC1 = NULL, *tmp_point = NULL;
	BIGNUM *bnPrikey = NULL, *h = NULL, *x2 = NULL, *y2 = NULL;
	unsigned char b_x2y2[2*GM_ECC_512_BYTES_LEN];
	unsigned char *t = NULL, *decPlaintext = NULL, sm3Digest[GM_HASH_BYTES_LEN], *c1, *c2 , *c3 ;
	int x2Len, y2Len;
	unsigned int i;
	gm_hash_context gm_hashCtx;
	unsigned int uPlaintextLen;

	if(!g_group512)
	{
		nRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!ciphertext || uCiphertextLen<=( 2*GM_ECC_512_BYTES_LEN + 1 + GM_HASH_BYTES_LEN) 
		|| !prikey || 0==uPrikeyLen || uPrikeyLen>GM_ECC_512_BYTES_LEN || !puPlaintextLen)
	{
		nRet=OPE_ERR_INVALID_PARAM;
		goto err;
	}

	uPlaintextLen = uCiphertextLen -( 2*GM_ECC_512_BYTES_LEN + 1 + GM_HASH_BYTES_LEN);
	if(!plaintext)
	{
		*puPlaintextLen = uPlaintextLen;
		nRet = 0;  // OK
		goto err;
	}
	if(*puPlaintextLen < uPlaintextLen)
	{
		*puPlaintextLen = uPlaintextLen;
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	ctx = BN_CTX_new();
	if (!ctx) 
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	BN_CTX_start(ctx);

	bnPrikey = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);
	if( !bnPrikey || !h || !x2 || !y2)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	t = OPENSSL_malloc(uPlaintextLen);
	c1 = ciphertext;
	c2 = ciphertext + (2*GM_ECC_512_BYTES_LEN+1);
	c3 = ciphertext + (2*GM_ECC_512_BYTES_LEN+1) + uPlaintextLen;
	decPlaintext = OPENSSL_malloc(uPlaintextLen);
	if( !t || !decPlaintext)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	memset(t, 0x00, uPlaintextLen);
	memset(decPlaintext, 0x00, uPlaintextLen);

	BN_bin2bn(prikey, uPrikeyLen ,bnPrikey);

	ptC1 = EC_POINT_new(g_group512);
	if (!ptC1) 
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	// 解析获得c1对应的点ptC1
	nRet = ParsePoint(ctx, c1, 2*GM_ECC_512_BYTES_LEN+1, ptC1);
	if(0 != nRet)
		goto err;

	if(!EC_POINT_is_on_curve(g_group512, ptC1, ctx))
	{
		nRet = -1;
		goto err;
	}

	tmp_point = EC_POINT_new(g_group512);
	if (!tmp_point) 
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	// tmp_point = S = [h]C1
	if (!EC_GROUP_get_cofactor(g_group512, h, ctx)) 
	{
		nRet = -1;
		goto err;
	}
	if (!EC_POINT_mul(g_group512, tmp_point, NULL, ptC1, h, ctx)) 
	{
		nRet = -1;
		goto err;
	}
	if (EC_POINT_is_at_infinity(g_group512, tmp_point)) 
	{
		nRet = -1;
		goto err;
	}

	// [dB]C1 = (x2, y2)
	if (!EC_POINT_mul(g_group512, tmp_point, NULL, ptC1, bnPrikey, ctx)) 
	{
		nRet = -1;
		goto err;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(g_group512, tmp_point, x2, y2, ctx))
	{
		nRet = -1;
		goto err;
	}

	// b_x2y2 = x2 || y2
	// 注意x2, y2 可能不够GM_ECC_512_BYTES_LEN字节, 按照标准, 前补0x00, 类似的地方有很多
	memset(b_x2y2, 0x00, sizeof(b_x2y2));

	x2Len = BN_num_bytes(x2);
	y2Len = BN_num_bytes(y2);
	if( (x2Len>GM_ECC_512_BYTES_LEN) || (x2Len>GM_ECC_512_BYTES_LEN) )
	{
		nRet = -1;
		goto err;
	}
	x2Len = BN_bn2bin(x2, b_x2y2 + GM_ECC_512_BYTES_LEN - x2Len);
	y2Len = BN_bn2bin(y2, b_x2y2 + 2*GM_ECC_512_BYTES_LEN - y2Len);

	// t = kdf(x2||y2, uPlaintextLen), uPlaintextLen is keylen
	nRet = gm_hash_kdf(t, uPlaintextLen, b_x2y2, 2*GM_ECC_512_BYTES_LEN,EHASH_TYPE_ZY_HASH_256);
	if( 0 != nRet)
		goto err;
	// check t 是否是全0x00
	for( i = 0; i< uPlaintextLen; i++)
	{
		if( 0x00 != t[i])
			break;
	}
	if( i == uPlaintextLen)    // 如果t是全0x00, err
	{
		nRet = -1;
		goto err;
	}

	// decPlaintext = c2 (bitwise) t
	for( i = 0; i< uPlaintextLen; i++)
		decPlaintext[i] = c2[i] ^ t[i];

	// sm3Digest = SM3(x2||plaintext||y2)
	memset(&gm_hashCtx,0x00,sizeof(gm_hashCtx));

	gm_hash_starts(&gm_hashCtx);
	gm_hash_update(&gm_hashCtx, b_x2y2, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, decPlaintext, uPlaintextLen);
	gm_hash_update(&gm_hashCtx, b_x2y2+GM_ECC_512_BYTES_LEN, GM_ECC_512_BYTES_LEN);
	gm_hash_finish(&gm_hashCtx, sm3Digest, EHASH_TYPE_ZY_HASH_256);

	// check sm3Digest = c3 or not
	if(0 != memcmp(c3, sm3Digest,  GM_HASH_BYTES_LEN))
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	// get plaintext 
	memcpy(plaintext, decPlaintext, uPlaintextLen );
	*puPlaintextLen = uPlaintextLen;

	if(t)
		OPENSSL_free(t);
	if(decPlaintext)
		OPENSSL_free(decPlaintext);
	
	if (ptC1)
		EC_POINT_free(ptC1);
	if (tmp_point)
		EC_POINT_free(tmp_point);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}

	return 0;
err:
	if(t)
		OPENSSL_free(t);
	if(decPlaintext)
		OPENSSL_free(decPlaintext);
	
	if (ptC1)
		EC_POINT_free(ptC1);
	if (tmp_point)
		EC_POINT_free(tmp_point);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return nRet;
}


int tcm_gmecc512_get_usrinfo_value(unsigned char *userID, unsigned int uUserIDLen, unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char digest[GM_HASH_MAX_BYTES_LEN], EHASH_TYPE hash_type)
{
	int nRet;
	unsigned int uUserIDBitLen;
	BN_CTX *ctx = NULL;
	EC_POINT *ptPubkey=NULL;
	BIGNUM *bn_xID = NULL, *bn_yID = NULL;
	unsigned char a[GM_ECC_512_BYTES_LEN], b[GM_ECC_512_BYTES_LEN], xG[GM_ECC_512_BYTES_LEN], yG[GM_ECC_512_BYTES_LEN];
	unsigned char entlUserID[2];
	unsigned char xID[GM_ECC_512_BYTES_LEN], yID[GM_ECC_512_BYTES_LEN];
	gm_hash_context gm_hashCtx;
	int xIDLen, yIDLen;

	if(!g_group512)
	{
		nRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}
	if(!userID || 0==uUserIDLen || !pubkey || 0==uPubkeyLen)
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	uUserIDBitLen = uUserIDLen << 3;
	// 按照定义, uUserIDBitLen最多两字节
	if(uUserIDBitLen > 0xFFFF)
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}
	// get entlUserID
	entlUserID[0] = (unsigned char)(uUserIDBitLen>>8);
	entlUserID[1] = (unsigned char)uUserIDBitLen;

	ctx = BN_CTX_new();
	if (!ctx) 
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	ptPubkey = EC_POINT_new(g_group512);
	if(!ptPubkey)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	// 解析获得公钥对应的点ptPubkey
	nRet = ParsePoint(ctx, pubkey, uPubkeyLen, ptPubkey);
	if( 0 != nRet)
		goto err;

	bn_xID = BN_new();
	bn_yID = BN_new();
	if( !bn_xID || !bn_yID)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(g_group512, ptPubkey, bn_xID, bn_yID, ctx)) 
	{
		nRet = -1;
		goto err;
	}

	// 计算xID与yID时, 注意在xID与yID的长度不满GM_ECC_512_BYTES_LEN时, 加前导0x00
	memset(xID, 0x00, sizeof(xID));
	memset(yID, 0x00, sizeof(yID));
	xIDLen = BN_num_bytes(bn_xID);
	yIDLen = BN_num_bytes(bn_yID);
	if( xIDLen>GM_ECC_512_BYTES_LEN || yIDLen>GM_ECC_512_BYTES_LEN)
	{
		nRet = -1;
		goto err;
	}
	xIDLen = BN_bn2bin(bn_xID, xID + GM_ECC_512_BYTES_LEN - xIDLen);
	yIDLen = BN_bn2bin(bn_yID, yID + GM_ECC_512_BYTES_LEN - yIDLen);

	MyStrToHexA(sz_a,sizeof(sz_a)-1,a);
	MyStrToHexA(sz_b,sizeof(sz_b)-1,b);
	MyStrToHexA(sz_xG,sizeof(sz_xG)-1,xG);
	MyStrToHexA(sz_yG,sizeof(sz_yG)-1,yG);


	// digest = SM3(entlUserID||userID||a||b||xG||yG||xID||yID)
	memset(&gm_hashCtx,0x00,sizeof(gm_hashCtx));

	gm_hash_starts(&gm_hashCtx);
	gm_hash_update(&gm_hashCtx, entlUserID, 2);
	gm_hash_update(&gm_hashCtx, userID, uUserIDLen);
	gm_hash_update(&gm_hashCtx, a, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, b, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, xG, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, yG, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, xID, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, yID, GM_ECC_512_BYTES_LEN);
	gm_hash_finish(&gm_hashCtx, digest, hash_type);

	if(bn_xID)
		BN_clear_free(bn_xID);
	if(bn_yID)
		BN_clear_free(bn_yID);

	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if(ctx)
		BN_CTX_free(ctx);
	return 0;
err:
	if(bn_xID)
		BN_clear_free(bn_xID);
	if(bn_yID)
		BN_clear_free(bn_yID);

	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if(ctx)
		BN_CTX_free(ctx);
	return nRet;
}


int tcm_gmecc512_get_message_hash(unsigned char *msg, unsigned int msgLen, unsigned char  *userID, unsigned int uUserIDLen, 
	unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char *digest, unsigned int *puDigestLen)
{
	int nRet;
	unsigned char zIDDigest[GM_HASH_MAX_BYTES_LEN];
	gm_hash_context gm_hashCtx;

	if(!g_group512)
	{
		nRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}
	if(!userID || 0==uUserIDLen || !pubkey || 0==uPubkeyLen || !puDigestLen )
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	if(!digest)
	{
		*puDigestLen = GM_HASH_BYTES_LEN*2;
		nRet = 0;  // OK
		goto err;
	}
	if(*puDigestLen < GM_HASH_BYTES_LEN*2)
	{
		*puDigestLen = GM_HASH_BYTES_LEN*2;
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	nRet = tcm_gmecc512_get_usrinfo_value(userID, uUserIDLen, pubkey, uPubkeyLen, zIDDigest, EHASH_TYPE_ZY_HASH_512);
	if(0 != nRet)
		goto err;

	// digest = SM3(entlUserID||userID||a||b||xG||yG||xID||yID)
	memset(&gm_hashCtx,0x00,sizeof(gm_hashCtx));

	gm_hash_starts(&gm_hashCtx);
	gm_hash_update(&gm_hashCtx, zIDDigest, GM_HASH_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, msg, msgLen);
	gm_hash_finish(&gm_hashCtx, digest, EHASH_TYPE_ZY_HASH_512);

	*puDigestLen = GM_HASH_BYTES_LEN*2;

	return 0;
err:
	return nRet;
}


int tcm_gmecc512_signature( unsigned char *digest, unsigned int uDigestLen, unsigned char *prikey, unsigned int uPrikeyLen, /*out*/unsigned char *sig, /*out*/unsigned int *puSigLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	BIGNUM *k = NULL, *r = NULL, *order = NULL, *order2 = NULL, *x1 = NULL, *s = NULL;
	BIGNUM *bnOne = NULL, *bnDigest = NULL, *bnPrikey = NULL , *bnTemp = NULL;
	EC_POINT *tmp_point = NULL;
	unsigned char bR[GM_ECC_512_BYTES_LEN], bS[GM_ECC_512_BYTES_LEN];
	int rLen, sLen;

	if(!g_group512)
	{
		nRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!digest || 0==uDigestLen || !prikey || 0==uPrikeyLen || !puSigLen)
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}
	
	if(!sig)
	{
		*puSigLen = 2 * GM_ECC_512_BYTES_LEN;
		nRet = 0;    // OK
		goto err;
	}
	if(*puSigLen < 2 * GM_ECC_512_BYTES_LEN)
	{
		*puSigLen = 2 * GM_ECC_512_BYTES_LEN;
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	ctx = BN_CTX_new();
	if(!ctx)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
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
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	BN_bin2bn(digest, uDigestLen, bnDigest);    // get bnDigest
	BN_bin2bn(prikey, uPrikeyLen, bnPrikey);	// get bnPrikey
	BN_one(bnOne);    //  bnOne = 1;

	tmp_point = EC_POINT_new(g_group512);
	if (!tmp_point)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	// get order
	if (!EC_GROUP_get_order(g_group512, order, ctx))
	{
		nRet = -1;
		goto err;
	}

	while(1){
		// generate random k
		do{
			if (!BN_rand_range(k, order)) 
			{
				nRet = -1;
				goto err;
			} 
		}while (BN_is_zero(k));

		// tmp_point = [k]G
		if (!EC_POINT_mul(g_group512, tmp_point, k, NULL, NULL, ctx)) 
		{
			nRet = -1;
			goto err;
		}
		if (!EC_POINT_get_affine_coordinates_GFp(g_group512, tmp_point, x1, NULL, ctx))
		{
			nRet = -1;
			goto err;
		}
		// r = (bnDigest + x1) mod order
		if (!BN_mod_add(r, x1, bnDigest, order, ctx)) 
		{
			nRet = -1;
			goto err;
		}

		if(BN_is_zero(r))
			continue;
		// r + k = order ?
		if (!BN_add(order2, r, k)) 
		{
			nRet = -1;
			goto err;
		}
		if( 0 == BN_ucmp(order, order2) )
			continue;

		// bnTemp = bnPrikey + 1 mod order
		if (!BN_mod_add(bnTemp, bnPrikey, bnOne, order, ctx)) 
		{
			nRet = -1;
			goto err;
		}
		// bnTemp = (bnPrikey + 1)^{-1} mod order
		if (!BN_mod_inverse(bnTemp, bnTemp, order, ctx))
		{
			nRet = -1;
			goto err;
		}

		// s = r*bnPrikey mod order
		if (!BN_mod_mul(s, bnPrikey, r, order, ctx)) 
		{
			nRet = -1;
			goto err;
		}
		// s = (k - r*bnPrikey) mod order
		if (!BN_mod_sub(s, k, s, order, ctx)) 
		{
			nRet = -1;
			goto err;
		}
		// s = ((bnPrikey + 1)^{-1}) * (k - r*bnPrikey) mod order
		if (!BN_mod_mul(s, bnTemp, s, order, ctx)) 
		{
			nRet = -1;
			goto err;
		}

		if(BN_is_zero(s))
			continue;

		break;
	}

	rLen=BN_bn2bin(r,bR);
	sLen=BN_bn2bin(s,bS);

	// return value
	memset(sig, 0x00,  2 * GM_ECC_512_BYTES_LEN);
	memcpy(sig + GM_ECC_512_BYTES_LEN - rLen, bR, rLen);
	memcpy(sig + 2*GM_ECC_512_BYTES_LEN - sLen, bS, sLen);
	*puSigLen = 2 * GM_ECC_512_BYTES_LEN;

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
	return nRet;
}


int tcm_gmecc512_verify(unsigned char *digest, unsigned int uDigestLen, unsigned char *sig, unsigned int uSigLen, unsigned char *pubkey, unsigned int uPubkeyLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	BIGNUM *t = NULL, *r = NULL, *r2 = NULL, *order = NULL, *x1 = NULL, *s = NULL;
	BIGNUM *bnDigest = NULL;
	EC_POINT *ptPubkey = NULL, *point = NULL;
	unsigned char *bR, *bS;   // bR, bS needn't free

	if(!g_group512)
	{
		nRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!digest || 0==uDigestLen || !sig || ((2*GM_ECC_512_BYTES_LEN)!=uSigLen) || !pubkey || 0==uPubkeyLen )
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	ctx = BN_CTX_new();
	if(!ctx)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
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
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	BN_bin2bn(digest, uDigestLen, bnDigest);    // get bnDigest

	bR=sig;
	bS=sig+GM_ECC_512_BYTES_LEN;

	BN_bin2bn(bR, GM_ECC_512_BYTES_LEN, r);
	BN_bin2bn(bS, GM_ECC_512_BYTES_LEN, s);

	// get order
	if (!EC_GROUP_get_order(g_group512, order, ctx))
	{
		nRet = -1;
		goto err;
	}
	
	// check r in [1, order-1], s in [1, order-1]
	if (BN_is_zero(r) || BN_is_negative(r) || BN_ucmp(r, order) >= 0 ||
		BN_is_zero(s) || BN_is_negative(s) || BN_ucmp(s, order) >= 0) 
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	// t = (r + s) mod order
	if (!BN_mod_add(t, r, s, order, ctx)) 
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}
	if(BN_is_zero(t))
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	ptPubkey = EC_POINT_new(g_group512);
	point = EC_POINT_new(g_group512);
	if (!ptPubkey || !point)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	nRet = ParsePoint(ctx, pubkey, uPubkeyLen, ptPubkey);
	if(0 != nRet)
		goto err;

	// point = [s]G + [t]ptPubkey
	if (!EC_POINT_mul(g_group512, point, s, ptPubkey, t, ctx)) 
	{
		nRet = -1;
		goto err;
	}

	if (!EC_POINT_get_affine_coordinates_GFp(g_group512, point, x1, NULL, ctx))
	{
		nRet = -1;
		goto err;
	}

	// r2 = (bnDigest + x1) mod order
	if (!BN_mod_add(r2, bnDigest, x1, order, ctx)) 
	{
		nRet = -1;
		goto err;
	}

	if(0 != BN_ucmp(r, r2))
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if (point)
		EC_POINT_free(point);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return 0;
err:
	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if (point)
		EC_POINT_free(point);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return nRet;
}


int tcm_gmecc512_exchange(unsigned char fA, unsigned char prikey_A[GM_ECC_512_BYTES_LEN], unsigned char pubkey_A[(GM_ECC_512_BYTES_LEN*2)+1], unsigned char prikey_RA[GM_ECC_512_BYTES_LEN], unsigned char pubkey_RA[(GM_ECC_512_BYTES_LEN*2)+1],
	unsigned char pubkey_B[(GM_ECC_512_BYTES_LEN*2)+1], unsigned char pubkey_RB[(GM_ECC_512_BYTES_LEN*2)+1], unsigned char Za[GM_ECC_512_BYTES_LEN], unsigned char Zb[GM_ECC_512_BYTES_LEN], /*out*/unsigned char key[16],
	/*out*/unsigned char S1[32], /*out*/unsigned char Sa[32], int keyLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	BIGNUM *order = NULL, *h = NULL, *x1 = NULL, *y1 = NULL, *x1_=NULL, *x2 = NULL, *y2 = NULL, *x2_=NULL, *xU = NULL, *yU=NULL ;
	BIGNUM *bnTemp = NULL, *bnPrikeyA = NULL, *tA = NULL, *rA = NULL;
	EC_POINT *ptRA = NULL, *ptPubkeyB = NULL, *ptRB = NULL, *tmp_point = NULL, *tmp_point2 = NULL;
	int orderBits, w;
	unsigned char bxU[GM_ECC_512_BYTES_LEN], byU[GM_ECC_512_BYTES_LEN];
	int xULen, yULen;
	unsigned char bx1[GM_ECC_512_BYTES_LEN], by1[GM_ECC_512_BYTES_LEN],bx2[GM_ECC_512_BYTES_LEN], by2[GM_ECC_512_BYTES_LEN];
	int x1Len, y1Len, x2Len, y2Len;
	unsigned char *pKdfInData = NULL;
	unsigned char tmp_digest[GM_HASH_BYTES_LEN], tag[1];
	gm_hash_context gm_hashCtx;

	if(!g_group512)
	{
		nRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	ctx = BN_CTX_new();
	if(!ctx)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	BN_CTX_start(ctx);

	order = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);
	x1 = BN_CTX_get(ctx);
	y1 = BN_CTX_get(ctx);
	x1_ = BN_CTX_get(ctx);
	x2 = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);
	x2_ = BN_CTX_get(ctx);
	xU = BN_CTX_get(ctx);
	yU = BN_CTX_get(ctx);
	tA = BN_CTX_get(ctx);
	rA = BN_CTX_get(ctx);
	bnPrikeyA = BN_CTX_get(ctx);
	bnTemp = BN_CTX_get(ctx);
	if ( !order || !h || !x1 || !y1 || !x1_ || !x2 || !y2 || !x2_ || !xU || !yU  || !tA || !rA || !bnPrikeyA || !bnTemp) 
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	BN_bin2bn(prikey_A, GM_ECC_512_BYTES_LEN, bnPrikeyA);
	BN_bin2bn(prikey_RA, GM_ECC_512_BYTES_LEN, rA);

	// get order
	if (!EC_GROUP_get_order(g_group512, order, ctx))
	{
		nRet = -1;
		goto err;
	}

	// w = [orderBits/2] - 1
	orderBits = BN_num_bits(order);
	w = orderBits/2;
	if(orderBits%2)
		w++;
	w--;

	// 
	ptRA = EC_POINT_new(g_group512);
	ptPubkeyB = EC_POINT_new(g_group512);
	ptRB = EC_POINT_new(g_group512);
	tmp_point = EC_POINT_new(g_group512);
	tmp_point2 = EC_POINT_new(g_group512);
	if (!ptRA || !ptPubkeyB || !ptRB || !tmp_point || !tmp_point2)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	// pubkey_RA -->ptRA
	nRet = ParsePoint(ctx, pubkey_RA, 2*GM_ECC_512_BYTES_LEN+1, ptRA);
	if(0 != nRet)
		goto err;

	if (!EC_POINT_get_affine_coordinates_GFp(g_group512, ptRA, x1, y1, ctx))
	{
		nRet = -1;
		goto err;
	}

	// x1_ = 2^w + (x1 & (2^w -1))
	BN_copy(x1_, x1);
	BN_mask_bits(x1_, w);
	BN_set_bit(x1_, w);

	// bnTemp = (x1_ * rA) mod order
	if(!BN_mod_mul(bnTemp, x1_, rA, order, ctx))
	{
		nRet = -1;
		goto err;
	}
	// tA = (dA + x1_ * rA) mod order
	if(!BN_mod_add(tA, bnTemp, bnPrikeyA, order, ctx))
	{
		nRet = -1;
		goto err;
	}

	// 验证pubkey_RB是否满足曲线
	if(!tcm_gmecc512_is_point_valid(pubkey_RB, 2*GM_ECC_512_BYTES_LEN+1))
	{
		nRet = -1;
		goto err;
	}

	// pubkey_RB -->ptRB
	nRet = ParsePoint(ctx, pubkey_RB, 2*GM_ECC_512_BYTES_LEN+1, ptRB);
	if(0 != nRet)
		goto err;

	if (!EC_POINT_get_affine_coordinates_GFp(g_group512, ptRB, x2, y2, ctx))
	{
		nRet = -1;
		goto err;
	}

	// x2_ = 2^w + (x2 & (2^w -1))
	BN_copy(x2_, x2);
	BN_mask_bits(x2_, w);
	BN_set_bit(x2_, w);

	// pubkey_B -->ptPubkeyB
	nRet = ParsePoint(ctx, pubkey_B, 2*GM_ECC_512_BYTES_LEN+1, ptPubkeyB);
	if(0 != nRet)
		goto err;

	// tmp_point = [x2_]ptRB
	if (!EC_POINT_mul(g_group512, tmp_point, 0, ptRB, x2_, ctx)) 
	{
		nRet = -1;
		goto err;
	}

	// tmp_point2 = ptPubkeyB + [x2_]ptRB
	if (!EC_POINT_add(g_group512, tmp_point2, tmp_point, ptPubkeyB, ctx)) 
	{
		nRet = -1;
		goto err;
	}

	// h
	if (!EC_GROUP_get_cofactor(g_group512, h, ctx)) 
	{
		nRet = -1;
		goto err;
	}

	// bnTemp = (h * tA) mod order
	if(!BN_mod_mul(bnTemp, tA, h, order, ctx))
	{
		nRet = -1;
		goto err;
	}

	// tmp_point = [h * tA] (ptPubkeyB + [x2_]ptRB)
	if (!EC_POINT_mul(g_group512, tmp_point, 0, tmp_point2, bnTemp, ctx)) 
	{
		nRet = -1;
		goto err;
	}
	if (EC_POINT_is_at_infinity(g_group512, tmp_point))
	{
		nRet = -1;
		goto err;
	}

	// (xU, yU) = [h * tA] (ptPubkeyB + [x2_]ptRB)
	if (!EC_POINT_get_affine_coordinates_GFp(g_group512, tmp_point, xU, yU, ctx))
	{
		nRet = -1;
		goto err;
	}

	xULen = BN_num_bytes(xU);
	yULen = BN_num_bytes(yU);

	memset(bxU, 0x00, sizeof(bxU));
	memset(byU, 0x00, sizeof(byU));
	xULen = BN_bn2bin(xU, bxU + GM_ECC_512_BYTES_LEN - xULen);
	yULen = BN_bn2bin(yU, byU + GM_ECC_512_BYTES_LEN - yULen);

	// pKdfInData
	pKdfInData = (unsigned char*) OPENSSL_malloc(2*GM_ECC_512_BYTES_LEN + 2*GM_HASH_BYTES_LEN);
	if(!pKdfInData)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}
	memset(pKdfInData, 0x00, 2*GM_ECC_512_BYTES_LEN + 2*GM_HASH_BYTES_LEN);
	memcpy(pKdfInData, bxU, GM_ECC_512_BYTES_LEN);
	memcpy(pKdfInData + GM_ECC_512_BYTES_LEN, byU, GM_ECC_512_BYTES_LEN);
	if(fA)
	{
		memcpy(pKdfInData + 2* GM_ECC_512_BYTES_LEN, Za, GM_HASH_BYTES_LEN);
		memcpy(pKdfInData + 2* GM_ECC_512_BYTES_LEN + GM_HASH_BYTES_LEN, Zb, GM_HASH_BYTES_LEN);
	}
	else
	{
		memcpy(pKdfInData + 2* GM_ECC_512_BYTES_LEN, Zb, GM_HASH_BYTES_LEN);
		memcpy(pKdfInData + 2* GM_ECC_512_BYTES_LEN + GM_HASH_BYTES_LEN, Za, GM_HASH_BYTES_LEN);
	}

	// get key, must 16 bytes
	nRet = gm_hash_kdf( key, keyLen, pKdfInData, 2*GM_ECC_512_BYTES_LEN + 2*GM_HASH_BYTES_LEN, EHASH_TYPE_ZY_HASH_256);
	if(0 != nRet)
		goto err;

	// bx1, by1, bx2, by2
	x1Len = BN_num_bytes(x1);
	y1Len = BN_num_bytes(y1);

	memset(bx1, 0x00, sizeof(bx1));
	memset(by1, 0x00, sizeof(by1));
	x1Len = BN_bn2bin(x1, bx1 + GM_ECC_512_BYTES_LEN - x1Len);
	y1Len = BN_bn2bin(y1, by1 + GM_ECC_512_BYTES_LEN - y1Len);

	x2Len = BN_num_bytes(x2);
	y2Len = BN_num_bytes(y2);

	memset(bx2, 0x00, sizeof(bx2));
	memset(by2, 0x00, sizeof(by2));
	x2Len = BN_bn2bin(x2, bx2 + GM_ECC_512_BYTES_LEN - x2Len);
	y2Len = BN_bn2bin(y2, by2 + GM_ECC_512_BYTES_LEN - y2Len);

	// tmp_digest = SM3(xU || Za || Zb || x1 || y1 || x2 || y2)
	memset(&gm_hashCtx, 0x00, sizeof(gm_hashCtx));
	gm_hash_starts(&gm_hashCtx);
	gm_hash_update(&gm_hashCtx, bxU, GM_ECC_512_BYTES_LEN);
	if(fA)
	{
		gm_hash_update(&gm_hashCtx, Za, GM_HASH_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, Zb, GM_HASH_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, bx1, GM_ECC_512_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, by1, GM_ECC_512_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, bx2, GM_ECC_512_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, by2, GM_ECC_512_BYTES_LEN);
	}
	else
	{
		gm_hash_update(&gm_hashCtx, Zb, GM_HASH_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, Za, GM_HASH_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, bx2, GM_ECC_512_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, by2, GM_ECC_512_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, bx1, GM_ECC_512_BYTES_LEN);
		gm_hash_update(&gm_hashCtx, by1, GM_ECC_512_BYTES_LEN);
	}

	gm_hash_finish(&gm_hashCtx, tmp_digest,EHASH_TYPE_ZY_HASH_256);

	// S1 = SM3(0x02 || yU || tmp_digest)
	tag[0] = 0x02;
	memset(&gm_hashCtx, 0x00, sizeof(gm_hashCtx));
	gm_hash_starts(&gm_hashCtx);
	gm_hash_update(&gm_hashCtx, tag, 1);
	gm_hash_update(&gm_hashCtx, byU, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, tmp_digest, GM_HASH_BYTES_LEN);
	gm_hash_finish(&gm_hashCtx, S1, EHASH_TYPE_ZY_HASH_256);

	// Sa = SM3(0x03 || yU || tmp_digest)
	tag[0] = 0x03;
	memset(&gm_hashCtx, 0x00, sizeof(gm_hashCtx));
	gm_hash_starts(&gm_hashCtx);
	gm_hash_update(&gm_hashCtx, tag, 1);
	gm_hash_update(&gm_hashCtx, byU, GM_ECC_512_BYTES_LEN);
	gm_hash_update(&gm_hashCtx, tmp_digest, GM_HASH_BYTES_LEN);
	gm_hash_finish(&gm_hashCtx, Sa, EHASH_TYPE_ZY_HASH_256);

	if(pKdfInData)
		OPENSSL_free(pKdfInData);

	if(ptRA)
		EC_POINT_free(ptRA);
	if(ptPubkeyB)
		EC_POINT_free(ptPubkeyB);
	if(ptRB)
		EC_POINT_free(ptRB);
	if(tmp_point)
		EC_POINT_free(tmp_point);
	if(tmp_point2)
		EC_POINT_free(tmp_point2);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return 0;
err:
	if(pKdfInData)
		OPENSSL_free(pKdfInData);

	if(ptRA)
		EC_POINT_free(ptRA);
	if(ptPubkeyB)
		EC_POINT_free(ptPubkeyB);
	if(ptRB)
		EC_POINT_free(ptRB);
	if(tmp_point)
		EC_POINT_free(tmp_point);
	if(tmp_point2)
		EC_POINT_free(tmp_point2);

	if(ctx)
	{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return nRet;
}

// if success return 1, otherwise return 0.
unsigned char tcm_gmecc512_is_point_valid(unsigned char *point, unsigned int uPointLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	EC_POINT *ptPoint=NULL;

	if(!g_group512)
		goto err;

	// check paramter
	if(!point || 0==uPointLen)
		goto err;

	ctx = BN_CTX_new();
	if (!ctx) 
		goto err;

	ptPoint = EC_POINT_new(g_group512);
	if(!ptPoint)
		goto err;

	// 解析获得point对应的点ptPoint
	nRet = ParsePoint(ctx, point, uPointLen, ptPoint);
	if( 0 != nRet)
		goto err;

	// 检查ptPoint是否在曲线上
	if(!EC_POINT_is_on_curve(g_group512, ptPoint, ctx))
		goto err;

	if (ptPoint)
		EC_POINT_free(ptPoint);
	if(ctx)
		BN_CTX_free(ctx);
	return 1;
err:
	if (ptPoint)
		EC_POINT_free(ptPoint);
	if(ctx)
		BN_CTX_free(ctx);
	return 0;
}


// if success return 1, otherwise return 0.
unsigned char tcm_gmecc512_point_to_uncompressed(unsigned char *point, unsigned int uPointLen, unsigned char *uncompressedpoint, unsigned int *puUncompressedpointLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	EC_POINT *ptPoint=NULL;

	if(!g_group512)
		goto err;

	if(!point || !uncompressedpoint || !puUncompressedpointLen)
		goto err;

	ctx = BN_CTX_new();
	if (!ctx) 
		goto err;

	ptPoint = EC_POINT_new(g_group512);
	if(!ptPoint)
		goto err;

	// 解析获得point对应的点ptPoint
	nRet = ParsePoint(ctx, point, uPointLen, ptPoint);
	if( 0 != nRet)
		goto err;

	// 检查ptPoint是否在曲线上
	if(!EC_POINT_is_on_curve(g_group512, ptPoint, ctx))
		goto err;

	// return pubkey
	*puUncompressedpointLen = 2*GM_ECC_512_BYTES_LEN + 1;
	nRet=PackagePoint(ctx, uncompressedpoint, puUncompressedpointLen, ptPoint, 0x04);
	if(0 != nRet)
		goto err;

	if (ptPoint)
		EC_POINT_free(ptPoint);
	if(ctx)
		BN_CTX_free(ctx);

	return 1;
err:
	if (ptPoint)
		EC_POINT_free(ptPoint);
	if(ctx)
		BN_CTX_free(ctx);

	return 0;
}


int tcm_gmecc512_genkey(unsigned char *prikey, unsigned int *puPrikeyLen, unsigned char *pubkey, unsigned int *puPubkeyLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	unsigned char bPrikey[GM_ECC_512_BYTES_LEN];
	int prikeyLen;
	EC_KEY *ecKey=NULL;
	EC_POINT *ptPubkey;   // needn't free
	BIGNUM *bnPrikey;     // needn't free

	if(!g_group512)
	{
		nRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!puPrikeyLen || !puPubkeyLen)
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}
	if(!prikey || !pubkey)
	{
		*puPrikeyLen = GM_ECC_512_BYTES_LEN;
		*puPubkeyLen = 2*GM_ECC_512_BYTES_LEN + 1;
		nRet = 0;    // OK
		goto err;
	}
	if( (*puPrikeyLen < GM_ECC_512_BYTES_LEN) || (*puPubkeyLen < (2*GM_ECC_512_BYTES_LEN + 1)))
	{
		*puPrikeyLen = GM_ECC_512_BYTES_LEN;
		*puPubkeyLen = 2*GM_ECC_512_BYTES_LEN + 1;
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	ctx = BN_CTX_new();
	if (!ctx) 
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	ecKey = EC_KEY_new();
	if (!ecKey)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	if(!EC_KEY_set_group(ecKey, g_group512))
	{
		nRet = -1;
		goto err;
	}

	if(!EC_KEY_generate_key(ecKey))
	{
		nRet = -1;
		goto err;
	}
	if (!EC_KEY_check_key(ecKey)) 
	{
		nRet = -1;
		goto err;
	}

	bnPrikey = (BIGNUM *)EC_KEY_get0_private_key(ecKey);
	ptPubkey = (EC_POINT*)EC_KEY_get0_public_key(ecKey);
	if(!bnPrikey || !ptPubkey)
	{
		nRet = -1;
		goto err;
	}

	// prikey
	prikeyLen = BN_num_bytes(bnPrikey);
	if(prikeyLen > GM_ECC_512_BYTES_LEN)
	{
		nRet = -1;
		goto err;
	}
	prikeyLen = BN_bn2bin( bnPrikey , bPrikey );

	// return pubkey
	nRet=PackagePoint(ctx, pubkey, puPubkeyLen, ptPubkey, 0x04);
	if(0 != nRet)
		goto err;

	// return prikey
	memset(prikey, 0x00, GM_ECC_512_BYTES_LEN);
	memcpy(prikey + GM_ECC_512_BYTES_LEN - prikeyLen, bPrikey, prikeyLen );
	*puPrikeyLen = GM_ECC_512_BYTES_LEN;

	if (ecKey)
		EC_KEY_free(ecKey);
	if(ctx)
		BN_CTX_free(ctx);
	return 0;
err:
	if (ecKey)
		EC_KEY_free(ecKey);
	if(ctx)
		BN_CTX_free(ctx);
	return nRet;
}


int tcm_gmecc512_point_from_privatekey(const unsigned char *prikey, const unsigned int uPrikeyLen, unsigned char *pubkey, unsigned int *puPubkeyLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	EC_POINT *ptPubkey = NULL;
	BIGNUM *bnPrikey = NULL;

	if(!g_group512)
	{
		nRet = OPE_ERR_INITIALIZE_OPENSSL;
		goto err;
	}

	if(!prikey || (0==uPrikeyLen) || !puPubkeyLen)
	{
		nRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}
	if(!pubkey)
	{
		*puPubkeyLen = 2*GM_ECC_512_BYTES_LEN + 1;
		nRet = 0;    // OK
		goto err;
	}
	if (*puPubkeyLen < (2*GM_ECC_512_BYTES_LEN + 1))
	{
		*puPubkeyLen = 2*GM_ECC_512_BYTES_LEN + 1;
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	ctx = BN_CTX_new();
	if (!ctx) 
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	bnPrikey = BN_new();
	if(!bnPrikey)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	BN_bin2bn(prikey, uPrikeyLen, bnPrikey);

	ptPubkey = EC_POINT_new(g_group512);
	if(!ptPubkey)
	{
		nRet = OPE_ERR_NOT_ENOUGH_MEMORY;
		goto err;
	}

	// ptPubkey = [bnPrikey]G
	if (!EC_POINT_mul(g_group512, ptPubkey, bnPrikey, NULL, NULL, ctx))
	{
		nRet = -1;
		goto err;
	}
	// return pubkey
	nRet=PackagePoint(ctx, pubkey, puPubkeyLen, ptPubkey, 0x04);
	if(0 != nRet)
		goto err;

	if(bnPrikey)
		BN_clear_free(bnPrikey);
	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if(ctx)
		BN_CTX_free(ctx);
	return 0;
err:
	if(bnPrikey)
		BN_clear_free(bnPrikey);
	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if(ctx)
		BN_CTX_free(ctx);
	return nRet;
}


unsigned char tcm_gmecc512_is_key_match(const unsigned char *prikey, const unsigned int uPrikeyLen, const unsigned char *pubkey, const unsigned int uPubkeyLen)
{
	int nRet;
	BN_CTX *ctx = NULL;
	EC_POINT *ptPubkey = NULL, *ptPubkey2 = NULL;
	BIGNUM *bnPrikey = NULL;

	if(!g_group512)
		goto err;
	if(!prikey || (0 == uPrikeyLen) || !pubkey || (0 == uPubkeyLen))
		goto err;

	ctx = BN_CTX_new();
	if (!ctx) 
		goto err;

	bnPrikey = BN_new();
	if(!bnPrikey)
		goto err;

	BN_bin2bn(prikey, uPrikeyLen, bnPrikey);

	ptPubkey = EC_POINT_new(g_group512);
	ptPubkey2 = EC_POINT_new(g_group512);
	if(!ptPubkey || !ptPubkey2)
		goto err;

	// ptPubkey = [bnPrikey]G
	if (!EC_POINT_mul(g_group512, ptPubkey, bnPrikey, NULL, NULL, ctx))
		goto err;

	nRet = ParsePoint(ctx, (unsigned char *)pubkey, uPubkeyLen, ptPubkey2);
	if(0 != nRet)
		goto err;

	if(0 != EC_POINT_cmp(g_group512, ptPubkey, ptPubkey2, ctx) )
		goto err;

	if(bnPrikey)
		BN_clear_free(bnPrikey);
	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if (ptPubkey2)
		EC_POINT_free(ptPubkey2);
	if(ctx)
		BN_CTX_free(ctx);
	return 1;
err:
	if(bnPrikey)
		BN_clear_free(bnPrikey);
	if (ptPubkey)
		EC_POINT_free(ptPubkey);
	if (ptPubkey2)
		EC_POINT_free(ptPubkey2);
	if(ctx)
		BN_CTX_free(ctx);
	return 0;
}


