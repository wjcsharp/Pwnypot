#pragma once
#include <Winsock2.h>
#include <stdlib.h>
#include <stdio.h>
#include <tlhelp32.h> 
#include <time.h>
#include <UrlMon.h>
#include "LogInfo.h"
#include "CuckooPipe.h"
#include "ETAV_DebugBreak.h"
#include "ModuleAutoInject.h"
#include "XmlLog.h"
#include "RopDetection.h"
#include "detours\detours.h"
#include "GeneralProtections.h"
#pragma comment(lib,"urlmon.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"detours\\detours_nodll.lib")
#pragma  comment(lib,"advapi32.lib")

#define ANALYSIS_TYPE_ROP 		"0"
#define ANALYSIS_TYPE_EXEC 		"1"
#define ANALYSIS_TYPE_DL2FILE	"2"
#define ANALYSIS_TYPE_SOCKET	"3"
#define ANALYSIS_TYPE_CONNECT	"4"
#define ANALYSIS_TYPE_LISTEN	"5"
#define ANALYSIS_TYPE_BIND		"6"
#define ANALYSIS_TYPE_ACCEPT	"7"
#define ANALYSIS_TYPE_SEND		"8"
#define ANALYSIS_TYPE_RECV		"9"
#define ANALYSIS_TYPE_API		"10"
#define ANALYSIS_TYPE_WPM		"11"
#define ANALYSIS_TYPE_SEH		"12"

/* parameter struct for LdrHotPatchRoutine as documented in https://docs.google.com/file/d/0B46UFFNOX3K7bl8zWmFvRGVlamM / https://github.com/0vercl0k/stuffz/blob/master/LdrHotPatchRoutine.c */
typedef struct
{
    ULONG o1;
    ULONG o2;

    USHORT PatcherNameOffset;
    USHORT PatcherNameLen;

    USHORT PatcheeNameOffset;
    USHORT PatcheeNameLen;

    USHORT UnknowNameOffset;
    USHORT UnknowNameLen;
} HOTPATCH;

typedef struct
{
    HOTPATCH a;
    WCHAR PatcherName[100];
    WCHAR PatcheeName[100];
} HotPatchBuffer;

static    BOOL (WINAPI *CreateProcessInternalW_ )(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken);
static  HANDLE (WINAPI *CreateThread_           )(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) = CreateThread;
static HRESULT (WINAPI *URLDownloadToFileW_     )(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB ) = URLDownloadToFileW;
static HRESULT (WINAPI *URLDownloadToFileA_     )(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB ) = URLDownloadToFileA;
static HMODULE (WINAPI *LoadLibraryExW_         )( LPCWSTR lpLibFileName,  HANDLE hFile,  DWORD dwFlags) = LoadLibraryExW;
static  SOCKET (WSAAPI *socket_                 )( int af, int type, int protocol ) = socket;
static  SOCKET (WSAAPI *accept_                 )( SOCKET s, struct sockaddr *addr, int *addrlen ) = accept;
static     int (WSAAPI *connect_                )( SOCKET s, const struct sockaddr *name, int namelen ) = connect;
static     int (WSAAPI *listen_                 )( SOCKET s, int backlog ) = listen;
static     int (WSAAPI *bind_                   )( SOCKET s, const struct sockaddr *name, int namelen ) = bind;
static     int (WSAAPI *send_                   )( SOCKET s, const char *buf, int len, int flags ) = send;
static     int (WSAAPI *recv_                   )( SOCKET s, char *buf, int len, int flags ) = recv;
static    BOOL (WINAPI *SetProcessDEPPolicy_	)(DWORD dwFlags) = SetProcessDEPPolicy;
static NTSTATUS(NTAPI  *NtSetInformationProcess_)(HANDLE hProcess, ULONG ProcessInformationClass, __in_bcount(ProcessInformationLength)PVOID ProcessInformation, ULONG ProcessInformationLength);
static    void (NTAPI *LdrHotPatchRoutine_		)(HotPatchBuffer * s_HotPatchBuffer);


typedef
NTSTATUS
(NTAPI *t_NtSetInformationProcess)(
	__in HANDLE ProcessHandle, 
	__in ULONG ProcessInformationClass,
	__in_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength
	);

typedef
VOID
(NTAPI *t_LdrHotPatchRoutine)(
	HotPatchBuffer * s_HotPatchBuffer
	);

extern PWNYPOTREGCONFIG PWNYPOT_REGCONFIG;
extern DWORD dwEaAccessCount;
extern BOOL bShellcodeDetected;
extern PXMLNODE XmlLog;
extern PXMLNODE XmlShellcode;
extern int (WSAAPI *TrueConnect		 )( SOCKET s, const struct sockaddr *name, int namelen ) ;
extern SOCKET (WSAAPI *TrueSocket    )( int af, int type, int protocol );
extern int (WSAAPI *TrueSend   )( SOCKET s, const char *buf, int len, int flags );

#define INIT_WAIT_TIME 2000

STATUS
HookInstall(
	VOID
	);

STATUS
HookUninstall(
	VOID
	);

HANDLE 
WINAPI 
HookedCreateThread(
	LPSECURITY_ATTRIBUTES lpThreadAttributes, 
	SIZE_T dwStackSize, 
	LPTHREAD_START_ROUTINE lpStartAddress, 
	LPVOID lpParameter, 
	DWORD dwCreationFlags, 
	LPDWORD lpThreadId
	);

BOOL
WINAPI
HookedCreateProcessInternalW(
	HANDLE hToken,
	LPCWSTR lpApplicationName,
	LPWSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCWSTR lpCurrentDirectory,
	LPSTARTUPINFOW lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation,
	PHANDLE hNewToken
	);

HRESULT
WINAPI
HookedURLDownloadToFileA(
    LPUNKNOWN pCaller,
    LPCTSTR szURL,
    LPCTSTR szFileName,
    DWORD dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
	);

HRESULT
WINAPI
HookedURLDownloadToFileW(
    LPUNKNOWN pCaller,
    LPCWSTR szURL,
    LPCWSTR szFileName,
    DWORD dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
	);

HMODULE 
WINAPI
HookedLoadLibraryExW(
	LPCWSTR lpLibFileName, 
	HANDLE hFile, 
	DWORD dwFlags
	);

extern "C"
LPVOID
WINAPI 
HookedMapViewOfFileEx(
	HANDLE hFileMappingObject, 
	DWORD dwDesiredAccess, 
	DWORD dwFileOffsetHigh, 
	DWORD dwFileOffsetLow, 
	SIZE_T dwNumberOfBytesToMap,
	LPVOID lpBaseAddress
	);

extern "C"
LPVOID
WINAPI 
HookedMapViewOfFile(
	HANDLE hFileMappingObject, 
	DWORD dwDesiredAccess, 
	DWORD dwFileOffsetHigh, 
	DWORD dwFileOffsetLow, 
	SIZE_T dwNumberOfBytesToMap
	);

extern "C"
BOOL
WINAPI
HookedVirtualProtectEx(
	HANDLE hProcess, 
	LPVOID lpAddress, 
	SIZE_T dwSize, 
	DWORD flAllocationType, 
	PDWORD flProtect
	);

extern "C"
BOOL
WINAPI
HookedVirtualProtect(
	LPVOID lpAddress, 
	SIZE_T dwSize, 
	DWORD flAllocationType, 
	PDWORD flProtect
	);

extern "C"
LPVOID
WINAPI
HookedVirtualAllocEx(
	HANDLE hProcess, 
	LPVOID lpAddress, 
	SIZE_T dwSize, 
	DWORD flAllocationType, 
	DWORD flProtect
	);

extern "C"
LPVOID
WINAPI 
HookedVirtualAlloc(
	LPVOID lpAddress, 
	SIZE_T dwSize, 
	DWORD flAllocationType, 
	DWORD flProtect
	);

extern "C"
HANDLE
WINAPI 
HookedHeapCreate(
	DWORD flOptions,
	SIZE_T dwInitialSize,
	SIZE_T dwMaximumSize
);

extern "C"
BOOL
WINAPI 
HookedWriteProcessMemory(
  __in 		HANDLE hProcess,
  __in 		LPVOID lpBaseAddress,
  __in 		LPCVOID lpBuffer,
  __in 		SIZE_T nSize,
  __out 	SIZE_T *lpNumberOfBytesWritten
);

SOCKET
WSAAPI
Hookedsocket(
	int af,
	int type,
	int protocol
	);

int
WSAAPI
Hookedconnect(
	SOCKET s,
    const struct sockaddr *name,
	int namelen
    );

int 
WSAAPI
UnhookedConnect (
	SOCKET s, 
	const struct sockaddr *name, 
	int namelen 
	);

int
WSAAPI
Hookedlisten(
	SOCKET s,
	int backlog
	);

int
WSAAPI
Hookedbind(
  SOCKET s,
  const struct sockaddr *name,
  int namelen
  );

SOCKET
WSAAPI
Hookedaccept(
	SOCKET s,
	struct sockaddr *addr,
	int *addrlen
	);


int
WSAAPI
Hookedsend(
	SOCKET s,
	const char *buf,
	int len,
	int flags
	);

int
WSAAPI
Hookedrecv(
	SOCKET s,
	char *buf,
	int len,
	int flags
	);

BOOL
WINAPI 
HookedSetProcessDEPPolicy(
	DWORD dwFlags
	);

NTSTATUS
NTAPI 
HookedNtSetInformationProcess(
	__in HANDLE ProcessHandle,
    __in ULONG ProcessInformationClass,
    __in_bcount (ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength
	);

VOID
NTAPI 
HookedLdrHotPatchRoutine(
	HotPatchBuffer * s_HotPatchBuffer
	);
