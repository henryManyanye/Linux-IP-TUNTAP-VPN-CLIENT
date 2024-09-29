// #include <linux/if.h>
#include <net/if.h>  
#include <linux/if_tun.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <openssl/evp.h>
#include <signal.h>
#include <time.h>

char packet2[4096];
socklen_t addrlen;
int n;

/* static void handler(int sig, siginfo_t *si, void *unused)
{
	printf("ALARM FOR STILL CONNECTED MESSAGE\n");
} */

int main(int argc, char const *argv[])
{
	/* struct sigaction sa;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = handler;

	sigaction(SIGALRM, &sa, NULL); */


	 int sfd;
	 sfd = socket(AF_INET, SOCK_STREAM, 0);
	 printf("socket(AF_INET...: %s %d\n", strerror(errno), errno);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(3030);
	addr.sin_addr.s_addr = inet_addr("172.16.0.1"); // THE IP ADDRESS OF MY DESKTOP SHOULD BE 172.16.0.2

	connect(sfd, (struct sockaddr *) &addr, sizeof addr);
	printf("connect 1...: %s %d\n", strerror(errno), errno);

	char message[1400] = "Hey there VPN SERVER. Linux client speaking";
	send(sfd, message, 1400, 0);
	printf("send...: %s %d\n", strerror(errno), errno);

	// recv(sfd, message, 1400, 0);
	recvfrom(sfd, message, 1400, 0, (struct sockaddr *)&addr, &addrlen);
	printf("recv...: %s %d\n", strerror(errno), errno);
	printf("FROM SERVER: %s\n", message);


	/********************* EXPERIMENT ***********************************/	
		char *localAddress;
		char *remoteAddressPrefix;
		char *route;
		char *routePrefix;
		char *mtu;

		char *remoteAddress;

		char *t;

		t = strtok(message, "&");

		localAddress = t;
	    printf("localAddress: %s\n", localAddress);

	    t = strtok(NULL, "&");
	    remoteAddressPrefix = t;
	    printf("remoteAddressPrefix: %s\n", remoteAddressPrefix);

	    t = strtok(NULL, "&");
	    route = t;
	    printf("route: %s\n", route);

	    t = strtok(NULL, "&");
	    routePrefix = t;
	    printf("routePrefix: %s\n", routePrefix);

	    t = strtok(NULL, "&");
	    mtu = t;
	    printf("mtu: %s\n", mtu);

	    t = strtok(NULL, "&");
	    remoteAddress = t;
	    printf("remoteAddress: %s\n", remoteAddress);

	/********************************************************************/



	close(sfd);

	int tunnel = socket(AF_INET, SOCK_DGRAM, 0);
	printf("socket(AF_INET...: %s %d\n", strerror(errno), errno);

	/* int flag = 0;
	setsockopt(tunnel, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));
	printf("setsockopt(tunnel...: %s %d\n", strerror(errno), errno); */

	struct sockaddr_in addr2;
	memset(&addr2, 0, sizeof(addr2));
	addr2.sin_family = AF_INET;
	addr2.sin_port = htons(2021);
	addr2.sin_addr.s_addr = inet_addr("172.16.0.1");

	connect(tunnel, (struct sockaddr *) &addr2, sizeof addr2);
	printf("connect 2...: %s %d\n", strerror(errno), errno);

	fcntl(tunnel, F_SETFL, O_NONBLOCK);
	printf("fcntl...: %s %d\n", strerror(errno), errno);

	int fd, err;
	if( (fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) < 0 )
	{
		printf("FAILED fd = open(...\n");
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	char *dev = "tun22";

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 )
	{
		close(fd);
		printf("FAILED ioctl(fd, TUNSETIFF...\n");
	}

	// struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(localAddress);
	// addr.sin_addr.s_addr = inet_addr("10.0.0.10");  // THIS PART WORKS

	memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));

	int sock = -1;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	printf("socket: %s %d\n", strerror(errno), errno);

	if( (err = ioctl(sock, SIOCSIFADDR, (void *) &ifr)) < 0 )
	{
		printf("FAILED ioctl(fd, SIOCSIFADDR...: %s %d\n", strerror(errno), errno);
		close(fd);
		 
	}

	ifr.ifr_flags = IFF_UP | IFF_NOARP | IFF_MULTICAST | IFF_POINTOPOINT;
	ioctl(sock, SIOCSIFFLAGS, (void *) &ifr);
	printf("ioctl(sock, SIOCSIFFLAGS... : %s %d\n", strerror(errno), errno);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(remoteAddress);
	// addr.sin_addr.s_addr = inet_addr("10.0.0.3"); // THIS PART WORKS
	memcpy(&ifr.ifr_dstaddr, &addr, sizeof(struct sockaddr));

	if( (err = ioctl(sock, SIOCSIFDSTADDR, (void *) &ifr)) < 0 )
	{
		printf("FAILED ioctl(fd, SIOCSIFDSTADDR...: %s %d\n", strerror(errno), errno);
		close(fd);
		 
	}

	close(sock);


	int fd3 = open("key.key", O_RDWR); // CHANGE THE URL ACCORDINGLY
	printf("fd3 = open key: %s %d\n", strerror(errno), errno);
	int fd4 = open("iv.iv", O_RDWR); // CHANGE THE URL ACCORDINGLY
	printf("fd4 = open iv: %s %d\n", strerror(errno), errno);

	unsigned char key[16];
	unsigned char iv[16];
	if(-1 == read(fd3, key, sizeof(key))) 
	{
		printf("-1 == read(fd3...: %s %d\n", strerror(errno), errno);

	}
	if(-1 == read(fd4, iv, sizeof(iv))) 
	{
		printf("-1 == read(fd4...: %s %d\n", strerror(errno), errno);

	}


	EVP_CIPHER_CTX *dectx;
	dectx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX *enctx;
	enctx = EVP_CIPHER_CTX_new();
	unsigned char outbuf[4096];				 
	int outlen;
	int outlen2;
	close(fd3);
	close(fd4);

	/***EXPERIMENT***/
		 unsigned char ZERO = 0;		
			time_t lastGreetingTime;
			lastGreetingTime = time(NULL);
	/****************/

	while(1)
	{
			if(1 != EVP_DecryptInit_ex(dectx, EVP_aes_128_cbc(), NULL, key, iv))	
			{
					printf("1 != EVP_DecryptInit_ex(dectx...: %s %d\n", strerror(errno), errno);
			}
			if(1 != EVP_EncryptInit_ex(enctx, EVP_aes_128_cbc(), NULL, key, iv))	
			{
					printf("1 != EVP_EncryptInit_ex(enctx...: %s %d\n", strerror(errno), errno);
			}


			outlen = 0;
			outlen2 = 0;

			/**********EXPERIMENT***************************/
			if((time(NULL) - lastGreetingTime) > 90)
			{			
			if(0 == EVP_CipherUpdate(enctx, outbuf, &outlen, &ZERO, sizeof (ZERO))) 
					{
						printf("0 == EVP_CipherUpdate(enctx...: %s %d\n", strerror(errno), errno);
					}else{
						printf("EVP_CipherUpdate enctx outlen :%d\n", outlen);
						
					}

				outlen2 += outlen;

			if(0 == EVP_CipherUpdate(enctx, outbuf + outlen, &outlen, "HEY SERVER. I AM STILL CONNECTED", strlen ("HEY SERVER. I AM STILL CONNECTED"))) 
					{
						printf("0 == EVP_CipherUpdate(enctx...: %s %d\n", strerror(errno), errno);
					}else{
						printf("EVP_CipherUpdate enctx outlen :%d\n", outlen);
						
					}

				outlen2 += outlen;
				outlen = outlen2;

			if(0 == EVP_CipherFinal_ex(enctx, outbuf + outlen, &outlen2))
					{
							printf("0 == EVP_CipherFinal_ex");
							
					}else{
							printf("EVP_CipherFinal_ex enctx outlen2 :%d\n", outlen2);
							
					}

			if (outlen2 != 0)
					{
						 n = send(tunnel, outbuf, outlen + outlen2, 0); 
						 printf("send: %s %d\n", strerror(errno), errno);

					}else{
						n = send(tunnel, outbuf, outlen, 0 ); 
						printf("send: %s %d\n", strerror(errno), errno);
					}

					printf("Bytes sent to UDP : %d\n", n);
					printf("\n");

			outlen = 0;
			outlen2 = 0;

			if(1 != EVP_EncryptInit_ex(enctx, EVP_aes_128_cbc(), NULL, key, iv))	
			{
					printf("1 != EVP_EncryptInit_ex(enctx...: %s %d\n", strerror(errno), errno);
			}
			lastGreetingTime = time(NULL);
			}
			/**************************************/

			n = read(fd, packet2, sizeof(packet2));
			if(n > 0)
			{
					printf("bytes RECVD FROM TUN0:%d\n", n);
					
					if(0 == EVP_CipherUpdate(enctx, outbuf, &outlen, packet2, n)) 
					{
						printf("0 == EVP_CipherUpdate(enctx...: %s %d\n", strerror(errno), errno);
					}else{
						printf("EVP_CipherUpdate enctx outlen :%d\n", outlen);
						
					}


					if(0 == EVP_CipherFinal_ex(enctx, outbuf + outlen, &outlen2))
					{
							printf("0 == EVP_CipherFinal_ex");
							
					}else{
							printf("EVP_CipherFinal_ex enctx outlen2 :%d\n", outlen2);
							
					}  

					if (outlen2 != 0)
					{
						 n = send(tunnel, outbuf, outlen + outlen2, 0); 
						 printf("send: %s %d\n", strerror(errno), errno);

					}else{
						n = send(tunnel, outbuf, outlen, 0 ); 
						printf("send: %s %d\n", strerror(errno), errno);
					}

					printf("Bytes sent to UDP : %d\n", n);
					printf("\n");


			}

			outlen = 0;
			outlen2 = 0;

			n = recvfrom(tunnel, packet2, sizeof(packet2), 0, (struct sockaddr *)&addr2, &addrlen);	 
			if(n > 0)
			{
					printf("Received %d bytes FROM UDP\n", n);

					if(0 == EVP_DecryptUpdate(dectx, outbuf, &outlen, packet2, n)) 
					{
							printf("0 == EVP_DecryptUpdate dectx \n");
							
					}else{
							printf("EVP_DecryptUpdate dectx outlen :%d\n", outlen);
							
					}
						
						if(0 == EVP_DecryptFinal_ex(dectx, outbuf + outlen, &outlen2))
					{
						  
							printf("0 == EVP_DecryptFinal_ex dectx outlen2 :%d\n", outlen2);
							printf("ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR ERROR\n");
							
					}else{
							printf("EVP_DecryptFinal_ex dectx outlen2 :%d\n", outlen2);
							
					}  

					 if (outlen != 0)
					 {
					 		n = write(fd, outbuf, outlen + outlen2);
					 }else{
					 		n = write(fd, outbuf, outlen);
					 }

					 printf("bytes WROTE to TUN0 :%d\n", n);
					 printf("\n");
			}				

	}

	close(fd);
	close(tunnel);
	EVP_cleanup();


	return 0;
}
