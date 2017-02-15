
#include "opf_kdf.h"
#include "sm3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int SM3_HashBuf(unsigned char *dest, const unsigned char *src, unsigned int src_length)
{
	sm3((unsigned char *)src,src_length,dest);
	return 0;
}

int opf_kdf(unsigned char *key, unsigned int key_len, unsigned char *SharedSecret, unsigned int SharedSecretLen,
		unsigned char *SharedInfo, unsigned int SharedInfoLen,
		int Hash(unsigned char *, const unsigned char *, unsigned int),
		unsigned int HashLen)
{
    unsigned char *buffer = NULL,*output_buffer = NULL;
    unsigned int buffer_len, max_counter, i;
    int rv = -1;

    /* Check that key_len isn't too long.  The maximum key length could be
     * greatly increased if the code below did not limit the 4-byte counter
     * to a maximum value of 255. */
	if (NULL == key)
	{
		return -1;
	}
	
    if (key_len > 254 * HashLen)
	{
		return -1;
	}

    if (SharedInfo == NULL)
	{
		SharedInfoLen = 0;
	}
	
    buffer_len = SharedSecretLen + 4 + SharedInfoLen;
    buffer = (unsigned char *)malloc(buffer_len);
    if (buffer == NULL) {
		rv = -1;
		goto err;
    }

    max_counter = key_len/HashLen;
    if (key_len > max_counter * HashLen)
	{
		max_counter++;
	}

	output_buffer = (unsigned char *)malloc(max_counter * HashLen);
	if (output_buffer == NULL) {
		rv = -1;
		goto err;
	}

    /* Populate buffer with SharedSecret || Counter || [SharedInfo]
     * where Counter is 0x00000001 */
    memcpy(buffer, SharedSecret, SharedSecretLen);
    buffer[SharedSecretLen] = 0;
    buffer[SharedSecretLen + 1] = 0;
    buffer[SharedSecretLen + 2] = 0;
    buffer[SharedSecretLen + 3] = 1;
    if (SharedInfo) {
		memcpy(&buffer[SharedSecretLen + 4], SharedInfo, SharedInfoLen);
    }

    for(i=0; i < max_counter; i++) {
		rv = Hash(&output_buffer[i * HashLen], buffer, buffer_len);
		if (rv != 0)
		{
			goto err;
		}

		/* Increment counter (assumes max_counter < 255) */
		buffer[SharedSecretLen + 3]++;
    }

    if (key_len < max_counter * HashLen) {
		memset(output_buffer + key_len, 0, max_counter * HashLen - key_len);
    }

	memcpy(key, output_buffer, key_len);

    rv = 0;

err:
	if (buffer) {
	    free(buffer);
	}

	if (output_buffer)
	{
		free(output_buffer);
	}
	
	return rv;
}
