
// gm-hash-512.h
#ifndef _GM_HASH_512_H_
#define _GM_HASH_512_H_


#define  GM_HASH_512_DIGEST_LEN     32

typedef struct {
	unsigned int total[2];
	unsigned int state[8];
	unsigned char buffer[64];
} gm_hash_512_context;


#ifdef __cplusplus
extern "C" {
#endif

/*
 * ����gm-hash-512 context
 * ctx gm-hash-512�����������
 */
void gm_hash_512_starts(gm_hash_512_context *ctx );

/*
 * �ṩ��������
 * ctx gm-hash-512�����������
 * input ��������
 * length �������ݳ���
 */
void gm_hash_512_update( gm_hash_512_context *ctx, unsigned char *input, unsigned int length);

/*
 * ������
 * ctx gm-hash-512�����������
 * digest �����Hashֵ
 */
void gm_hash_512_finish( gm_hash_512_context *ctx, unsigned char digest[32] );


/* 
 * ֱ�Ӹ������������
 * datalen_in �������ݳ���
 * pdata_in ��������
 * digest �����Hashֵ
 */
int gm_hash_512_hash( unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[32]);


int gm_hash_512_hmac(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char digest[32]);

int gm_hash_512_kdf(/*out*/unsigned char *key, /*in*/int klen, /*in*/unsigned char *z, /*in*/ int zlen);


#ifdef __cplusplus
}
#endif

#endif /* gm-hash-512.h */
