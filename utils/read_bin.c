#include <stdio.h>
#include <stdlib.h>

size_t len_frame1, len_frame2;

int main(int argc, char *argv[]){
		int i;
		FILE *fp;
		__uint8_t data;
		size_t len;
		char * filename = NULL;
		__uint8_t *__afl_key, *__afl_key1;
		int sz;
		
 if (argc >= 1 && argv[1] != NULL) {
        filename = argv[1];
    }


		fp=fopen(filename,"rb");
		if (!fp){
			printf("Unable to open file %s!\n",filename);
			return -1;
		}
		
		
		 fseek(fp, 0, SEEK_END);
    sz = ftell(fp);
    rewind(fp);



		int ret;
		 printf("\n------------------------------------------------------\n");
    printf("\n");
		printf("Reading Frame 1\n");
		fread(&len, sizeof(size_t), 1, fp);
		printf("Frame 1 len: %ld\n",len);

		for (i=0 ; i <= len; i++){
			fread(&data, sizeof(__uint8_t), 1, fp);
			printf("%d ", data);
		}
		
		printf("\n");
		 printf("\n------------------------------------------------------\n");
    printf("\n");
		
		printf("Reading Frame 2\n");
		fread(&len, sizeof(size_t), 1, fp);
		printf("Frame 2 len: %ld\n",len);
		
		for (i=0 ; i < len; i++){
			fread(&data, sizeof(__uint8_t), 1, fp);
			printf("%d ", data);
		}
		
		 printf("\n------------------------------------------------------\n");
    printf("\n");
		
		
		fclose(fp);
		return 0;
	}
	

	
	
	
	
