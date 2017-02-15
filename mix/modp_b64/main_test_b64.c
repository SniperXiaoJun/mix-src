#include <stdio.h>
#include <string.h>



int main()
{
	int len = 0;
	int i = 0;
	char * en = NULL;
	unsigned char * de = NULL;
	unsigned char * plain = NULL;
	
	

	for(i = 0;i < 1000000; i++)
	{
		len = rand() % 255 + 1;

		plain = malloc(len + 1);
		en = malloc(512);
		de = malloc(len + 1);
		random_byte(plain, len);

		len = modp_b64_encode(en, plain, len);
		len = modp_b64_decode(de, en,len);

		if((i+1) % 1000 == 0)
		{
			printf("\nplain:%s", plain);
			printf("\nen:%s", en);
			printf("\nde:%s", de);
			printf("\n:%d, %d", i,len);
		}

		if (0 != memcmp(de,plain, len))
		{
			printf("\nplain:%s", plain);
			printf("\nen:%s", en);
			printf("\nde:%s", de);
			printf("\n:%d, %d", i,len);
			printf("\n:error");
			break;
		}

		free(plain);
		free(en);
		free(de);
	}

	return 0;
}
