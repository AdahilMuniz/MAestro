#include <memphis.h>
#include <stdlib.h>
#include <stdio.h>

int main()
{

message_t msg;
int j;

	for(j=0;j<128;j++) msg.payload[j]=j;

	msg.length=128;
	for(j=0;j<8;j++) memphis_receive(&msg,IDCT2_0);
	msg.length=61;
	memphis_receive(&msg,IDCT2_0);
	msg.length=128;
	for(j=0;j<7;j++) memphis_send(&msg,VOPREC_0);
	msg.length=26;
	memphis_send(&msg,VOPREC_0);

	return 0;

}
