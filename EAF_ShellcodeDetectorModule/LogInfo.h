#pragma once
#include <WinSock2.h>
#include <stdio.h>
#include <tlhelp32.h> 
#include <time.h>
#include <UrlMon.h>
#include <Shlobj.h>
#include "detours\detours.h"

#define __DEBUG__
#define __OUTTMPFILE__
//#define __MSGBOx__
#define LSHL									1
#define LDBG									2
#define LROP									3

#define PWNYPOT_ERROR_BASE						0x13000000
#define PWNYPOT_STATUS_SUCCESS					PWNYPOT_ERROR_BASE
#define PWNYPOT_STATUS_NO_MORE_ENTRIES			PWNYPOT_ERROR_BASE+1
#define PWNYPOT_STATUS_INTERNAL_ERROR			PWNYPOT_ERROR_BASE+2
#define PWNYPOT_STATUS_PARTIAL_DISASSEMBLE		PWNYPOT_ERROR_BASE+3
#define PWNYPOT_STATUS_INVALID_ACCESS			PWNYPOT_ERROR_BASE+4
#define PWNYPOT_STATUS_VALID_ACCESS				PWNYPOT_ERROR_BASE+5
#define PWNYPOT_STATUS_GENERAL_FAIL				PWNYPOT_ERROR_BASE+6
#define PWNYPOT_STATUS_SHELLCODE_FLAG_NOT_SET	PWNYPOT_ERROR_BASE+7
#define PWNYPOT_STATUS_SHELLCODE_FLAG_SET		PWNYPOT_ERROR_BASE+8
#define PWNYPOT_STATUS_ROP_FLAG_SET				PWNYPOT_ERROR_BASE+9
#define PWNYPOT_STATUS_ROP_FLAG_NOT_SET			PWNYPOT_ERROR_BASE+10
#define PWNYPOT_STATUS_INSUFFICIENT_BUFFER		PWNYPOT_ERROR_BASE+11
#define PWNYPOT_STATUS_NORESPONSE				PWNYPOT_ERROR_BASE+12
#define PWNYPOT_STATUS_RESPONSE					PWNYPOT_ERROR_BASE+13
#define PWNYPOT_STATUS_OP_FREE					PWNYPOT_ERROR_BASE+14
#define PWNYPOT_STATUS_OP_BUSY					PWNYPOT_ERROR_BASE+15
#define PWNYPOT_STATUS_OP_SHELLCODE_DETECTED	PWNYPOT_ERROR_BASE+16

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#endif

#define UID_SIZE        50
#define SEC             1000
#define MAX_ERROR_MSG   256
typedef DWORD STATUS;


typedef struct _ERRORINFO {
	DWORD	dwErrorNum;
	CHAR	ErrorMsg[256];
	CHAR	*CompletErrorMsg;
} ERRORINFO, *PERRORINFO; 

extern "C"
VOID 
DEBUG_PRINTF(
	IN DWORD dwType,
	IN DWORD dwTID,
	IN PCHAR Format, 
	IN ...
	);

VOID 
REPORT_ERROR( 
	IN PCHAR Function,
	OUT PERRORINFO ErrorInfo
	);

VOID 
REPORT_ERROR_EX(
	IN PCHAR Function,
	IN DWORD dwErrorNumber,
	OUT PERRORINFO ErrorInfo
	);

BOOL 
FolderExists(
	LPTSTR szFolderName
	);

STATUS
InitLogPath(
	OUT PCHAR LogPath,
	IN DWORD Size
	);

PCHAR
strtolow(
    PCHAR szString
    );

PCHAR
GenRandomStr(
    PCHAR szString, 
    DWORD dwSize
    );

VOID
HexDumpToFile(
    PBYTE Data, 
    DWORD dwSize, 
    PCHAR szFileName
    );

#ifdef CUCKOO


VOID 
LOCAL_DEBUG_PRINTF(
    IN PCHAR Format, 
    IN ...
    );


STATUS
WriteFileSocket(
    SOCKET Socket,
    PCHAR Buffer
    );

STATUS
InitCuckooLogs();

STATUS
InitShellcodeLog();


STATUS
TransmitFile(
    PCHAR szLocalPath,
    PCHAR szFileName,
    PCHAR szRemotePath
    );

STATUS
TransmitBufAsFile(
    PCHAR szBuf,
    PCHAR szRemoteFileName
    );

STATUS
BufferedSend(
    SOCKET s,
    PCHAR szBuf
    );

#endif