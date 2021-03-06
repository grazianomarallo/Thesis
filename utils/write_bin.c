#include <stdio.h>

//frame eapol 4
static const unsigned char frame__[] = {
        0x01, 0x03, 0x00, 0x75, 0x02, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x89, 0xe9, 0x15, 0x65, 0x09, 0x4f,
        0x32, 0x9a, 0x9c, 0xd5, 0x4a, 0x4a, 0x09, 0x0d, 0x2c, 0xf4, 0x34, 0x46,
        0x83, 0xbf, 0x50, 0xef, 0xee, 0x36, 0x08, 0xb6, 0x48, 0x56, 0x80, 0x0e,
        0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc3, 0x1b,
        0x82, 0xff, 0x62, 0xa3, 0x79, 0xb0, 0x8d, 0xd1, 0xfc, 0x82, 0xc2, 0xf7,
        0x68, 0x00, 0x16, 0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01,
        0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00,
        0x00
};

//frame eapol 6
static const unsigned char frame_[] = {
        0x01, 0x03, 0x00, 0x5f, 0x02, 0x03, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9e, 0x57, 0xa4,
        0xc0, 0x9b, 0xaf, 0xb3, 0x37, 0x5e, 0x46, 0xd3, 0x86, 0xcf, 0x87, 0x27,
        0x53, 0x00, 0x00
};

//frame29
static const unsigned char frame1[] = {
   0x02, 0x03, 0x00, 0x5f, 0x02, 0x00, 0x89, 0x00, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x30, 0x37, 0x86,
        0x8d, 0x6c, 0xd2, 0x38, 0xb2, 0xfe, 0xb4, 0x5b, 0xd3, 0xc6,
        0x4b, 0xa1, 0x3e, 0x26, 0xd9, 0xa4, 0x89, 0x8b, 0x43, 0xf6,
        0x66, 0x51, 0x26, 0x99, 0x5e, 0x62, 0xce, 0x8e, 0x9d, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         
};

//frame 31
static const unsigned char frame2[] = {
        0x02, 0x03, 0x00, 0xd3, 0x02, 0x13, 0xc9, 0x00, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x30, 0x37, 0x86, 0x8d, 0x6c, 0xd2, 0x38,
        0xb2, 0xfe, 0xb4, 0x5b, 0xd3, 0xc6, 0x4b, 0xa1, 0x3e, 0x26, 0xd9, 0xa4,
        0x89, 0x8b, 0x43, 0xf6, 0x66, 0x51, 0x26, 0x99, 0x5e, 0x62, 0xce, 0x8e,
        0x9d, 0x92, 0xcf, 0x64, 0xa6, 0xf5, 0xea, 0x95, 0xf7, 0xf9, 0xeb, 0x6a,
        0x54, 0x8a, 0x85, 0x6c, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x80, 0xb3,
        0x14, 0x1f, 0xfa, 0x11, 0x47, 0xcd, 0x6d, 0xd0, 0x20, 0x7e, 0x9e, 0x68,
        0x65, 0x00, 0x74, 0x39, 0xf4, 0xc9, 0x3a, 0xf3, 0xac, 0xf5, 0xd3, 0x98,
        0xeb, 0xaf, 0x3c, 0x0f, 0xf1, 0xb5, 0x33, 0xff, 0xb2, 0x00, 0x1b, 0xe4,
        0x2c, 0x61, 0xaf, 0xff, 0x1c, 0x22, 0x76, 0x07, 0x3b, 0xbc, 0x0d, 0x0c,
        0xeb, 0x8a, 0xdc, 0xcd, 0x47, 0x01, 0xa5, 0x6e, 0x76, 0x77, 0x85, 0x6f,
        0x09, 0x43, 0x83, 0xee, 0x50, 0x6e, 0x5e, 0xb1, 0x24, 0xe3, 0x47, 0xef,
        0x20, 0x5e, 0x5c, 0x10, 0x7a, 0xe3, 0x61, 0x69, 0x7b, 0xb0, 0xf6, 0xdd,
        0x42, 0x1a, 0xe1, 0xc9, 0x33, 0xd6, 0xd3, 0x88, 0x40, 0xcc, 0x72, 0x28,
        0x86, 0xce, 0xec, 0xea, 0xc0, 0xea, 0xc9, 0xcf, 0xe1, 0x93, 0x8b, 0x15,
        0x5e, 0xbb, 0x1f, 0xf9, 0x6f, 0x10, 0x34, 0xa5, 0xfc, 0x61, 0x78, 0x77,
        0xa7, 0xb1, 0x4d, 0xc4, 0x36, 0xea, 0x2f, 0x1d, 0xda, 0x31, 0xa1,
};

size_t len_frame1, len_frame2,len_frame3;

int main(int argc, char *argv[]){
		int i;
		FILE *fp;
		__uint8_t data;
		char * filename = NULL;
		
		 if (argc >= 1 && argv[1] != NULL) {
        filename = argv[1];
    }

		fp=fopen(filename,"wb");
		if (!fp){
			printf("Unable to open file %s\n",filename);
			return -1;
		}
		
		len_frame1 = sizeof(frame1);
		len_frame2 = sizeof(frame2);
		
		
		printf("Writing frame 1\n");
		fwrite(&len_frame1, sizeof(size_t), 1, fp);
		printf("Len written %ld\n",len_frame1);
		for (i=0 ; i <= len_frame1; i++){
			 data = frame1[i];
			 printf("%d ",data);
			fwrite(&data, sizeof(__uint8_t), 1, fp);
		}
		
		
		printf("\n\n");
		printf("Writing frame 2\n");
		fwrite(&len_frame2, sizeof(size_t), 1, fp);
		printf("Len written %ld\n",len_frame2);
		for (i=0 ; i <= len_frame2; i++){
			 data = frame2[i];
			  printf("%d ",data);
			fwrite(&data, sizeof(__uint8_t), 1, fp);
		}
		
	/*	printf("Writing frame 3\n");
		fwrite(&len_frame3, sizeof(size_t), 1, fp);
		for (i=0 ; i <= len_frame3; i++){
			 data = frame3[i];
			fwrite(&data, sizeof(__uint8_t), 1, fp);
		}
	
	
		*/
		printf("\n\n");
		fclose(fp);

		
		printf("Closing\n");
		return 0;
	}
	
