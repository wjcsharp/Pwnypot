#pragma once
#include "LogInfo.h"
#include "ParseConfig.h"

extern PWNYPOTREGCONFIG PWNYPOT_REGCONFIG;
BOOL bLogPathInitSuccess = FALSE;

#ifdef CUCKOO
SOCKET LogInfoSock = -1;
SOCKET LogRopSock = -1;
SOCKET LogShellcodeSock = -1;
#else 
BOOL bLogStart = FALSE;
#endif


int     (WSAAPI * TrueConnect   )(SOCKET s, const struct sockaddr *name, int namelen ) = NULL;
SOCKET  (WSAAPI * TrueSocket    )(int af, int type, int protocol ) = NULL;
int     (WSAAPI * TrueSend      )( SOCKET s, const char *buf, int len, int flags ) = NULL;

VOID 
REPORT_ERROR( 
	IN PCHAR Function,
	OUT PERRORINFO ErrorInfo
	)
{
	ErrorInfo->dwErrorNum = GetLastError();
    REPORT_ERROR_EX( Function,
		             GetLastError(),
				     ErrorInfo);
}

VOID 
REPORT_ERROR_EX(
	IN PCHAR Function,
	IN DWORD dwErrorNumber,
	OUT PERRORINFO ErrorInfo
	)
{
	BOOL bErrorHandle;
	HMODULE hErrorDllHandle;

	if ( TRUE ) /* Check for EAF_CONFIG.DISABLE_LOGGING */
	{
		ErrorInfo->dwErrorNum = dwErrorNumber;
		bErrorHandle = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
									  NULL,
									  ErrorInfo->dwErrorNum,
									  MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
									  ErrorInfo->ErrorMsg,
									  256,
									  NULL);
		if ( bErrorHandle == FALSE )
		{
			/* load library and check the error again for network related errors */
			hErrorDllHandle = LoadLibraryEx("netmsg.dll",
											 NULL,
											 DONT_RESOLVE_DLL_REFERENCES);
			if ( hErrorDllHandle != NULL )
			{
				bErrorHandle = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
											  NULL,
											  ErrorInfo->dwErrorNum,
											  MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
											  ErrorInfo->ErrorMsg,
											  256,
											  NULL);
			}
		}
		if ( bErrorHandle == FALSE )
		{
			strncpy(ErrorInfo->ErrorMsg,"Unknown Error", 256);
		}

		/* allocate memory for completed error message */
		ErrorInfo->CompletErrorMsg = (CHAR *) LocalAlloc( LMEM_ZEROINIT, 512 );
        _snprintf( ErrorInfo->CompletErrorMsg , MAX_ERROR_MSG, "[!] ERROR : %s failed with error %d (%s)\n", Function, ErrorInfo->dwErrorNum, ErrorInfo->ErrorMsg );
		DEBUG_PRINTF(LDBG, NULL, "%s",ErrorInfo->CompletErrorMsg);
        /* This should free by caller */
        LocalFree(ErrorInfo->CompletErrorMsg);
	}
}


STATUS
InitLogPath(
	OUT PCHAR LogPath,
	IN DWORD Size
	)
{
	CHAR szLogPath[MAX_PATH];
	SYSTEMTIME lt;

    if ( bLogPathInitSuccess )
        return PWNYPOT_STATUS_SUCCESS;

	SecureZeroMemory(szLogPath, MAX_PATH);
	GetLocalTime( &lt);
	/* init log path by time stamp */
	_snprintf( szLogPath, MAX_PATH, "\\%d.%d.%d ,%d-%d-%d-%d", lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
	strncat( LogPath,  szLogPath ,Size );

	if ( FolderExists( LogPath ) )
    {
        bLogPathInitSuccess = TRUE;
		return PWNYPOT_STATUS_SUCCESS;
    }

	if ( CreateDirectory( LogPath, NULL ) )
    {
        bLogPathInitSuccess = TRUE;
		return PWNYPOT_STATUS_SUCCESS;
    }

	return PWNYPOT_STATUS_INTERNAL_ERROR;	
}


BOOL 
FolderExists(
	LPTSTR szFolderName
	)
{   
    return (GetFileAttributes(szFolderName) != INVALID_FILE_ATTRIBUTES) ? TRUE : FALSE;   
}

PCHAR
strtolow(
    PCHAR szString
    )
{
    PCHAR Container;
    Container = szString;

	while(*Container) 
    {
        *Container = tolower(*Container);
		Container++;
	}

	return szString;
}




PCHAR
GenRandomStr(
    PCHAR szString, 
    DWORD dwSize
    ) 
{
    DWORD dwSeed;
    CONST CHAR alphanum[] = "0123456789abcdefghijklmnopqrstuvwxyz";

    Sleep(100);
    dwSeed = ((DWORD)&dwSeed >> 8) ^ (GetTickCount() >> 8) ^ GetCurrentThreadId();
    srand(dwSeed);

    for (int i = 0; i < dwSize; ++i)
        szString[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

    szString[dwSize] = 0;
    return szString;
}



#ifndef CUCKOO

VOID
HexDumpToFile(
    PBYTE Data, 
    DWORD dwSize, 
    PCHAR szFileName
    ) 
{
   UINT dp, p;
   FILE *fp;
   CHAR szFullLogPath[MAX_PATH];
   CONST CHAR trans[] = "................................ !\"#$%&'()*+,-./0123456789"
                        ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
                        "nopqrstuvwxyz{|}~...................................."
                        "....................................................."
                        "........................................";
    
   strncpy( szFullLogPath, PWNYPOT_REGCONFIG.LOG_PATH, MAX_PATH );
   strncat(szFullLogPath, "\\", MAX_PATH);
   strncat(szFullLogPath, szFileName, MAX_PATH);

    fp = fopen(szFullLogPath, "a");
    if ( fp == NULL )
        return; 

    for (dp = 1; dp <= dwSize; dp++)  
    {
        fprintf(fp,"%02x ", Data[dp-1]);
        if ((dp % 8) == 0)
            fprintf(fp," ");
        if ((dp % 16) == 0) 
        {
            fprintf(fp,"| ");
            p = dp;
            for (dp -= 16; dp < p; dp++)
                fprintf(fp,"%c", trans[Data[dp]]);
            fprintf(fp,"\n");
        }
    }

    if ((dwSize % 16) != 0)
    {
        p = dp = 16 - (dwSize % 16);
        for (dp = p; dp > 0; dp--) 
        {
            fprintf(fp,"   ");
            if (((dp % 8) == 0) && (p != 8))
                fprintf(fp," ");
        }
        fprintf(fp," | ");
        for (dp = (dwSize - (16 - p)); dp < dwSize; dp++)
            fprintf(fp,"%c", trans[Data[dp]]);
    }
    fprintf(fp,"\n");
    fflush(fp);
    fclose(fp);
    return;
}

extern "C"
VOID 
DEBUG_PRINTF(
    IN DWORD dwType,
    IN DWORD dwTID,
    IN PCHAR Format, 
    IN ...
    )
{
    CHAR Buffer[1024] = {0};
    CHAR szFullLogPath[MAX_PATH];
    FILE *fp;
    va_list Args;

    va_start(Args, Format);
    vsnprintf_s(Buffer, sizeof Buffer, _TRUNCATE, Format, Args);
    va_end(Args);

    strncpy( szFullLogPath, PWNYPOT_REGCONFIG.LOG_PATH, MAX_PATH );
#ifdef __DEBUG__
    if ( dwType == LDBG )
    {
        strncpy( szFullLogPath, PWNYPOT_REGCONFIG.DBG_LOG_PATH, MAX_PATH );
        strncat( szFullLogPath, "\\LogInfo", MAX_PATH);
    }
#else
    if ( dwType == LDBG )
        return;
#endif
    else if ( dwType == LROP ) 
        strncat(szFullLogPath, "\\RopAnalysis", MAX_PATH);

    fflush(stdout);
    fflush(stderr);

    fp = fopen(szFullLogPath, "a");
    if ( fp == NULL )
        return;

    if ( !bLogStart )
    {
        fprintf(fp, "\n=========================================================================================\n");
        bLogStart = TRUE;
    }
    
    fprintf(fp, "%s", Buffer);
    fflush(fp);
    fclose(fp);
    return;
}


#else 

extern "C"
VOID 
DEBUG_PRINTF(
    IN DWORD dwType,
    IN DWORD dwTID,
    IN PCHAR Format, 
    IN ...
    )
{
    CHAR Buffer[1024] = {0};
    CHAR szFullLogPath[MAX_PATH];
    va_list Args;

    va_start(Args, Format);
    vsnprintf_s(Buffer, sizeof Buffer, _TRUNCATE, Format, Args);
    va_end(Args);

    strncpy( szFullLogPath, PWNYPOT_REGCONFIG.LOG_PATH, MAX_PATH );
#ifdef __DEBUG__
    if (  dwType == LDBG ){
        if( LogInfoSock != -1) 
            WriteFileSocket( LogInfoSock, Buffer );
        else             
            LOCAL_DEBUG_PRINTF("Could not write to Log Filesocket: %s\n",Buffer);
    }
#else
    if ( dwType == LDBG )
        return;
#endif
    else if ( dwType == LROP && PWNYPOT_REGCONFIG.ROP.DETECT_ROP)
    {
        if ( LogRopSock != -1 ){            
            WriteFileSocket( LogRopSock, Buffer );
        }
        else 
        {
            LOCAL_DEBUG_PRINTF("Could not write to ROP Filesocket: %s\n",Buffer);
        }
    }
    else if ( dwType == LSHL )
    {
        if ( LogShellcodeSock != -1 ){
            WriteFileSocket( LogShellcodeSock, Buffer );
        }
        else 
        {
            LOCAL_DEBUG_PRINTF("Could not write to Shellcode Filesocket: %s\n",Buffer);
        }
    }
    return;
}


VOID LOCAL_DEBUG_PRINTF (
    IN PCHAR Format, 
    IN ...
    )
{
    CHAR Buffer[2048] = {0};
    CHAR szFullLogPath[MAX_PATH];
    CHAR szPid [MAX_PATH];
    FILE *fp;
    va_list Args;

    va_start(Args, Format);
    vsnprintf_s(Buffer, sizeof Buffer, _TRUNCATE, Format, Args);
    va_end(Args);
    strncpy( szFullLogPath, PWNYPOT_REGCONFIG.DBG_LOG_PATH, MAX_PATH );
    sprintf(szPid, "\\%u_", GetCurrentProcessId(), MAX_PATH);
    strncat( szFullLogPath, szPid, MAX_PATH);
    strncat( szFullLogPath, "LogInfo", MAX_PATH);

    fflush(stdout);
    fflush(stderr);

    fp = fopen(szFullLogPath, "a");
    if ( fp == NULL )
        return;
    
    fprintf(fp, "%s", Buffer);
    fflush(fp);
    fclose(fp);
    return;
}

SOCKET 
InitFileSocket (
    PCHAR szFileName
    )
{
    SOCKET s;
    WSADATA wsadata;
    CHAR szPid[MAX_PATH];
    sprintf(szPid, "%u", GetCurrentProcessId(), MAX_PATH);

    LOCAL_DEBUG_PRINTF("Initializing File Socket %s for PID %s\n",szFileName,szPid);
    int error = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (error)
    {
        LOCAL_DEBUG_PRINTF("WSAStartup error\n");
        return -1;
    }

    if (wsadata.wVersion != MAKEWORD(2, 2))
    {
        LOCAL_DEBUG_PRINTF("Wrong version\n");
        return -1;
    }

    SOCKADDR_IN target; 

    target.sin_family = AF_INET; 
    target.sin_addr.s_addr = inet_addr (PWNYPOT_REGCONFIG.RESULT_SERVER_IP); 
    target.sin_port = htons ((unsigned int)PWNYPOT_REGCONFIG.RESULT_SERVER_PORT);
    s = TrueSocket (AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (s == INVALID_SOCKET)
    {
        LOCAL_DEBUG_PRINTF("Invalid Socket\n");
        return -1; 
    }  

    if ( (TrueConnect(s, (SOCKADDR *)&target, sizeof(target))) == SOCKET_ERROR)
    {
        LOCAL_DEBUG_PRINTF("Socket Error\n");
        return -1; 
    }
    else
    {
        const int LENGTH = 512;

        char buffer[256];

        memset(buffer, '\0', 256);
        strncpy(buffer, "FILE\nlogs/",256);
        strncat(buffer, szPid, 256);
        strncat(buffer, "_", 256);
        strncat(buffer, szFileName,256);
        strncat(buffer, "\n",256);
        if (BufferedSend(s,buffer) == PWNYPOT_STATUS_SUCCESS){
            LOCAL_DEBUG_PRINTF("Successfully Initialized FileSocket %s\n", szFileName);            
        }
        else {            
            LOCAL_DEBUG_PRINTF("Initialized FileSocket %s failed\n", szFileName);  
            return -1;
        }


    }
    return s;
}

STATUS 
WriteFileSocket (
    SOCKET Socket,
    PCHAR Buffer
    )
{   
    if ( BufferedSend(Socket, Buffer) == PWNYPOT_STATUS_INTERNAL_ERROR ) {
        LOCAL_DEBUG_PRINTF("Last error: %d\n", WSAGetLastError());
        return PWNYPOT_STATUS_INTERNAL_ERROR;
    }
    return PWNYPOT_STATUS_SUCCESS;
}

STATUS 
InitCuckooLogs ()
{
    TrueConnect = (int (WSAAPI *)( SOCKET , const struct sockaddr * , int ))DetourFindFunction("ws2_32.dll", "connect");
    TrueSocket = (SOCKET (WSAAPI *)( int , int , int ))DetourFindFunction("ws2_32.dll", "socket");
    TrueSend = (int (WSAAPI *)(SOCKET s, const char *, int , int ))DetourFindFunction("ws2_32.dll", "send");
    LOCAL_DEBUG_PRINTF("Initializing Cuckoo Socket Logs from PID: %u\n",GetCurrentProcessId());
    if ( bLogPathInitSuccess )
        return PWNYPOT_STATUS_SUCCESS;
    // init LogInfo.txt
    LogInfoSock = InitFileSocket("LogInfo");
    if (LogInfoSock==-1){
        return PWNYPOT_STATUS_INTERNAL_ERROR;
    }

    // init RopDetection.txt
    if(PWNYPOT_REGCONFIG.ROP.DETECT_ROP)
    {
        LogRopSock = InitFileSocket("RopAnalysis");
        if (LogRopSock==-1){
            return PWNYPOT_STATUS_INTERNAL_ERROR;
        }
    }

    LogShellcodeSock = InitFileSocket("LogShellcode");
    if (LogShellcodeSock==-1){
        return PWNYPOT_STATUS_INTERNAL_ERROR;
    }   


    bLogPathInitSuccess = TRUE;
    return PWNYPOT_STATUS_SUCCESS;
}

STATUS 
InitShellcodeLog ()
{
    LOCAL_DEBUG_PRINTF("Initializing Cuckoo Shellcode Logs from PID: %u\n",GetCurrentProcessId());
    if (LogShellcodeSock!=-1){
        return PWNYPOT_STATUS_SUCCESS;
    }
    return PWNYPOT_STATUS_SUCCESS;
}

STATUS 
TransmitFile (
    PCHAR szLocalPath,
	PCHAR szFileName,
    PCHAR szRemotePath
	)
{
    char *buffer;
    char szRemoteFile[MAX_PATH];
    char szFullPath[MAX_PATH];
    long fileLength;

    memset(szRemoteFile, '\0', MAX_PATH);
    strncpy(szRemoteFile, szRemotePath, MAX_PATH);
    strncat(szRemoteFile, szFileName, MAX_PATH);  

    strncpy(szFullPath, szLocalPath,MAX_PATH);
    strncat(szFullPath, "\\",MAX_PATH);
    strncat(szFullPath, szFileName,MAX_PATH);

    FILE *fs = fopen(szFullPath, "r");
    if(fs == NULL)
    {
        LOCAL_DEBUG_PRINTF("ERROR: Failed to open file for sending %s. (errno = %d)\n", szFullPath, errno);
        return PWNYPOT_STATUS_INTERNAL_ERROR;
    }

    fseek(fs, 0L, SEEK_END);
    fileLength = ftell(fs);
    fseek(fs, 0L, SEEK_SET);
    buffer = (char*)calloc(fileLength, sizeof(char)); 
    if(buffer == NULL)
        return PWNYPOT_STATUS_INTERNAL_ERROR;


    fread(buffer, sizeof(char), fileLength, fs);
    fclose(fs);

    STATUS result = TransmitBufAsFile(buffer, szRemoteFile);
    free(buffer);
    return result;
    
}


STATUS 
TransmitBufAsFile (
    PCHAR szBuf,
    PCHAR szRemoteFileName
    )
{
    SOCKET s;
    WSADATA wsadata;
    
    int error = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (error)
    {
        return PWNYPOT_STATUS_INTERNAL_ERROR;
    }

    if (wsadata.wVersion != MAKEWORD(2, 2))
    {
        WSACleanup(); //Clean up Winsock
        return PWNYPOT_STATUS_INTERNAL_ERROR;
    }

    SOCKADDR_IN target; 

    target.sin_family = AF_INET; 
    target.sin_addr.s_addr = inet_addr (PWNYPOT_REGCONFIG.RESULT_SERVER_IP); 
    target.sin_port = htons ((unsigned int)PWNYPOT_REGCONFIG.RESULT_SERVER_PORT); 
    s = TrueSocket (AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (s == INVALID_SOCKET)
    {
        LOCAL_DEBUG_PRINTF("ERROR: Invalid socket for file transmission.\n");
        return PWNYPOT_STATUS_INTERNAL_ERROR; 
    }  

    if (TrueConnect(s, (SOCKADDR *)&target, sizeof(target)) == SOCKET_ERROR)
    {
        LOCAL_DEBUG_PRINTF("ERROR: Failed to connect to socket for file transmission.\n");
        return PWNYPOT_STATUS_INTERNAL_ERROR; 
    }
    else
    {
        const int LENGTH = 512;
        char buffer[LENGTH];

        memset(buffer, '\0', LENGTH);
        strncpy(buffer, "FILE\n", LENGTH);
        strncat(buffer, szRemoteFileName, LENGTH);
        strncat(buffer, "\n",LENGTH);
        if (BufferedSend(s, buffer) == PWNYPOT_STATUS_INTERNAL_ERROR)
        {
            LOCAL_DEBUG_PRINTF("Failed to send remote Filename %s.\n", szRemoteFileName);
            return PWNYPOT_STATUS_INTERNAL_ERROR;
        }

        if( BufferedSend(s, szBuf) == PWNYPOT_STATUS_INTERNAL_ERROR){
            LOCAL_DEBUG_PRINTF("ERROR: Failed to send file %s. (errno = %d)\n", szRemoteFileName, errno);
            closesocket(s);
            return PWNYPOT_STATUS_INTERNAL_ERROR;            
        }
        closesocket(s);
        return PWNYPOT_STATUS_SUCCESS;
    }
}


VOID
HexDumpToFile(
    PBYTE Data, 
    DWORD dwSize, 
    PCHAR szFileName
    ) 
{
    UINT dp, p;
    const UINT dumpLength = 65536;
    const int tmpLength = 1024;
    CHAR szBuf[dumpLength];
    CHAR szTmp[tmpLength];
    CONST CHAR trans[] = "................................ !\"#$%&'()*+,-./0123456789"
                        ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
                        "nopqrstuvwxyz{|}~...................................."
                        "....................................................."
                        "........................................";

    for (dp = 1; dp <= dwSize; dp++)  
    { 
        memset(szTmp, '\0', tmpLength); 
        sprintf(szTmp,"%02x ", Data[dp-1], tmpLength);
        strncat(szBuf, szTmp, dumpLength);
        if ((dp % 8) == 0)
           strncat(szBuf," ", dumpLength);
        if ((dp % 16) == 0) 
        {
            strncat(szBuf,"| ", dumpLength);
            p = dp;
            for (dp -= 16; dp < p; dp++)
            {
                memset(szTmp, '\0', tmpLength); 
                sprintf(szTmp,"%c", trans[Data[dp]], tmpLength);
                strncat(szBuf, szTmp, dumpLength);
            }
            strncat(szBuf,"\n", dumpLength);
        }
    }

    if ((dwSize % 16) != 0)
    {
        p = dp = 16 - (dwSize % 16);
        for (dp = p; dp > 0; dp--) 
        {
            strncat(szBuf, "   ", dumpLength);
            if (((dp % 8) == 0) && (p != 8))
                strncat(szBuf, " ", dumpLength);
        }
        strncat(szBuf," | ", dumpLength);
        for (dp = (dwSize - (16 - p)); dp < dwSize; dp++)
        {
            memset(szTmp, '\0', tmpLength); 
            sprintf(szTmp, "%c", trans[Data[dp]], tmpLength);
            strncat(szBuf, szTmp, dumpLength);
        }
    }

    strncat(szBuf,"\n", dumpLength);
    memset(szTmp, '\0', tmpLength);
    sprintf(szTmp, "logs/%d_dump-%s\n", GetCurrentProcessId(), szFileName, tmpLength);    

    if (TransmitBufAsFile(szBuf, szTmp) == PWNYPOT_STATUS_INTERNAL_ERROR) 
        LOCAL_DEBUG_PRINTF("ERROR: Failed to send hexdump %s. (errno = %d)\n", szFileName, errno);
     
    else
        LOCAL_DEBUG_PRINTF("Sent hexdump %s\n", szFileName);
}

STATUS
BufferedSend (
    SOCKET s,
    PCHAR szBuf
    )
{
    int totalSend = 0;
    int currentSend = 0;
    while (totalSend < strlen(szBuf)){
        currentSend = TrueSend(s, szBuf+sizeof(char)*totalSend, strlen(szBuf)-totalSend, 0);
        if (currentSend < 0)
        {
            LOCAL_DEBUG_PRINTF("Buffered send: Send returned %d", currentSend);
            return PWNYPOT_STATUS_INTERNAL_ERROR;
        }
        totalSend += currentSend;
    }
    //LOCAL_DEBUG_PRINTF("Sent %d / %d  bytes\n", totalSend, strlen(szBuf));
    return PWNYPOT_STATUS_SUCCESS;
}


#endif
