
// gm-hash-bit.h
#ifndef _GM_HASH_H_
#define _GM_HASH_H_

#define  GM_HASH_BYTES_LEN         32

#define  GM_HASH_MIN_BYTES_LEN     32
#define  GM_HASH_256_BYTES_LEN     GM_HASH_MIN_BYTES_LEN

#define  GM_HASH_MAX_BYTES_LEN     64
#define  GM_HASH_512_BYTES_LEN     GM_HASH_MAX_BYTES_LEN

#define  GM_HASH_256_BYTES_XOR  "XORData_ZY_Hash_ABCDEF_Random_12"
#define  GM_HASH_512_BYTES_XOR  "ZY_HashTestXORData_12345678ABCDE"

typedef enum
{
	EHASH_TYPE_SM3,
	EHASH_TYPE_ZY_HASH_256,
	EHASH_TYPE_ZY_HASH_512,
}EHASH_TYPE;


typedef struct {
	unsigned int total[2];
	unsigned int state[8];
	unsigned char buffer[64];
} gm_hash_context;


#ifdef __cplusplus
extern "C" {
#endif

/*
 * 建立gm-hash-bit context
 * ctx gm-hash-bit计算的上下文
 */
void gm_hash_starts(gm_hash_context *ctx );

/*
 * 提供输入数据
 * ctx gm-hash-bit计算的上下文
 * input 输入数据
 * length 输入数据长度
 */
void gm_hash_update( gm_hash_context *ctx, unsigned char *input, unsigned int length);

/*
 * 计算结果
 * ctx gm-hash-bit计算的上下文
 * digest 输出的Hash值
 */
void gm_hash_finish( gm_hash_context *ctx, unsigned char digest[GM_HASH_MAX_BYTES_LEN], EHASH_TYPE hash_type);


/* 
 * 直接根据输入计算结果
 * datalen_in 输入数据长度
 * pdata_in 输入数据
 * digest 输出的Hash值
 */
int gm_hash_hash( unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[GM_HASH_MAX_BYTES_LEN], EHASH_TYPE hash_type);


int gm_hash_hmac(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char digest[GM_HASH_MAX_BYTES_LEN], EHASH_TYPE hash_type);

int gm_hash_kdf(/*out*/unsigned char *key, /*in*/int klen, /*in*/unsigned char *z, /*in*/ int zlen, EHASH_TYPE hash_type);


#ifdef __cplusplus
}
#endif

#endif /* gm-hash-bit.h */
