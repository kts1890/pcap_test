#include <pcap.h>

#include <stdio.h>

 

void usage() {

  printf("syntax: pcap_test <interface>\n");

  printf("sample: pcap_test wlan0\n");

}

 

int main(int argc, char* argv[]) {

    int ip_length;
    int tcp_length;
    int data_length;
    int total_length;
    char lowbit=0x0f;
  if (argc != 2) {

    usage();

    return -1;

  }

 

  char* dev = argv[1];

  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL) {

    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);

    return -1;

  }

 

  while (true) {

    struct pcap_pkthdr* header;

    const u_char* packet;

    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;

    if (res == -1 || res == -2) break;

    printf("%u bytes captured\n", header->caplen);

    printf("src mac : %02x",packet[6]);
    for(int i=7;i<12;i++){
        printf(":%02x",packet[i]);
    }
    printf("\ndst mac : %02x",packet[0]);
    for(int i=1;i<6;i++){
        printf(":%02x",packet[i]);
    }

    if(packet[12]==8 && packet[13]==0){
        if((packet[14]>>4)==4){
	    ip_length=(packet[14]&lowbit)*4;
	    printf("\nsrc ip : %d",packet[26]);
	    for(int i=27;i<30;i++){
		printf(".%d",packet[i]);
	    }
	    printf("\ndst ip : %d",packet[30]);
	    for(int i=31;i<34;i++){
		printf(".%d",packet[i]);
	    }
        }
	else if((packet[14]>>4)==6){
	    ip_length=packet[18]*256+packet[19];
	    printf("\nsrc ip : %02x%02x",packet[22],packet[23]);
	    for(int i=12;i<19;i++){
		printf(":%02x%02x",packet[i*2],packet[i*2+1]);
	    }
	    printf("\ndst ip : %02x%02x",packet[38],packet[39]);
	    for(int i=20;i<27;i++){
		printf(":%02x%02x",packet[i*2],packet[i*2+1]);
	    }
	    printf("\n");
        }
	if(packet[23]==6){
	   printf("\nsrc port : %d\ndst port : %d\n",packet[ip_length+16]*16+packet[ip_length+17] ,packet[ip_length+14]*16+packet[ip_length+15]);
	}
	total_length=packet[16]*256+packet[17];
	tcp_length=(packet[14+ip_length+12]>>4)*4;
	data_length=total_length-ip_length-tcp_length;
	if(data_length>0){
	    printf("data : ");
	    for(int i=0;i<data_length;i++){
	        if(i>=32)
		    break;
		printf("%02x ",packet[14+ip_length+tcp_length+i]);
	    }
	    printf("\n");
	}
    }
  }

 

  pcap_close(handle);

  return 0;

}


