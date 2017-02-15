

#ifndef __OPF_KDF__H
#define __OPF_KDF__H


#ifdef __cplusplus
extern "C" {
#endif

int SM3_HashBuf(unsigned char *dest, const unsigned char *src, unsigned int src_length);

int opf_kdf(unsigned char *key, unsigned int key_len, unsigned char *SharedSecret, unsigned int SharedSecretLen,
	unsigned char *SharedInfo, unsigned int SharedInfoLen,
	int Hash(unsigned char *, const unsigned char *, unsigned int),
	unsigned int HashLen);

#ifdef __cplusplus
}
#endif

#endif

