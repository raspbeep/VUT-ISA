/*

 Simple echo UDP server

 Usage: echo-udp-server2 <port number>


*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFER	(1024)

int main(int argc, char *argv[])
{
    int fd;
    struct sockaddr_in server;
    int n, r;
    char buffer[BUFFER];
    struct sockaddr_in client;
    socklen_t length;

    if (argc != 2)               // read the first parameter: a port number
        errx(1,"Usage %s <port number>",argv[0]);
    //    errx(1,"Usage %s <port number>",getprogname()); for FreeBSD only

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(atoi(argv[1]));

    printf("opening UDP socket(...)\n");
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        err(1, "socket() failed");

    printf("binding with the port %d (%d)\n",ntohs(server.sin_port), server.sin_port);
    if (bind(fd, (struct sockaddr *)&server, sizeof(server)) == -1)
        err(1, "bind() failed");
    length = sizeof(client);

    while ((n= recvfrom(fd, buffer, BUFFER, 0, (struct sockaddr *)&client, &length)) >= 0)
    {
        printf("data received from %s, port %d\n",inet_ntoa(client.sin_addr),ntohs(client.sin_port));

        for (r = 0; r < n; r++)
            if (islower(buffer[r]))
                buffer[r] = toupper(buffer[r]);
            else if (isupper(buffer[r]))
                buffer[r] = tolower(buffer[r]);

        r = sendto(fd, buffer, n, 0, (struct sockaddr *)&client, length); // send the answer
        if (r == -1)
            err(1, "sendto()");
        else if (r != n)
            errx(1, "sendto(): Buffer written just partially");
        else
            printf("data \"%.*s\" sent to %s, port %d\n",r,buffer,inet_ntoa(client.sin_addr),ntohs(client.sin_port));
    }
    printf("closing socket\n");
    close(fd);

    return 0;
}
