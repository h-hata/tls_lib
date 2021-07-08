#include <stdio.h>
#include <ctype.h>


void dump_packet(unsigned char *ptr,int len)
{
	unsigned char	*ptr1,*ptr2;
	int	count1=0;
	int	count2=0;
	int	i,j,k;
	char	c;
	printf("Packet len = %d(0x%X)bytes\n",len,len);
	for(i=0;;i++){
		ptr1=ptr2=ptr+i*16 ;
		for(j=0;j<16;j++){
			printf("%02X",*ptr2++);
			if(j==7){
				printf(" - ");
			}else{
				printf(" ");
			}
			count1++;
			if(count1 >= len ) break;
		}
		k = 16 - j-1;
		for(j=0; j < k ; j++) printf("   ");
		if(k > 8 )            printf("  ");
		ptr2=ptr1;
		for(j=0;j<16;j++){
			if(isprint(*ptr2)){
                              c=*ptr2;
			} else{
                              c='.';
			}
			ptr2++;
			printf("%1c",c);
			if(j==7){
				printf(" ");
			}
			count2++;
			if(count2 >= len ) {printf("\n\n");return ;}
		}
		printf("\n");
	}
}

