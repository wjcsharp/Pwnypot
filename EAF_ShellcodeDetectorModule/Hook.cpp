#include "Hook.h"

extern "C" /* ROP detection hooks */
{
	/* static  LPVOID (WINAPI *VirtualAlloc_           )(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc; */
	PVOID VirtualAlloc_ = (PVOID)VirtualAlloc;
	/* static  LPVOID (WINAPI *VirtualAllocEx_         )(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAllocEx; */
	PVOID VirtualAllocEx_ = (PVOID)VirtualAllocEx;
	/* static    BOOL (WINAPI *VirtualProtectEx_       )(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = VirtualProtectEx; */
	PVOID VirtualProtectEx_ = (PVOID)VirtualProtectEx;
	/* static    BOOL (WINAPI *VirtualProtect_         )(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = VirtualProtect; */
	PVOID VirtualProtect_ = (PVOID)VirtualProtect;
	/* static  LPVOID (WINAPI *MapViewOfFile_          )(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) = MapViewOfFile; */
	PVOID MapViewOfFile_ = (PVOID)MapViewOfFile;
	/* static  LPVOID (WINAPI *MapViewOfFileEx_        )(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress) = MapViewOfFileEx; */
	PVOID MapViewOfFileEx_ = (PVOID)MapViewOfFileEx;
	/* static  HANDLE (WINAPI *HeapCreate_			   )(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) = HeapCreate; */
	PVOID HeapCreate_ = (PVOID)HeapCreate;
	/* static  HANDLE (WINAPI *WriteProcessMemory_			   )(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) = HeapCreate; */
	PVOID WriteProcessMemory_ = (PVOID)WriteProcessMemory;

}

STATUS
HookInstall(
	VOID
	)
{

	LONG error;
	CreateProcessInternalW_ = (BOOL (WINAPI *)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE))GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "CreateProcessInternalW");
	NtSetInformationProcess_ = (t_NtSetInformationProcess)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtSetInformationProcess"));
	LdrHotPatchRoutine_ = (t_LdrHotPatchRoutine)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "LdrHotPatchRoutine"));
	DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

	/* CreateProcess should be hooked regardless of what type of protection is enabled */
	DetourAttach(&(PVOID&)CreateProcessInternalW_		, HookedCreateProcessInternalW);

    /* Hook virtual memory manipulation function needs for checking rop attacks */
	if ( PWNYPOT_REGCONFIG.ROP.DETECT_ROP )
	{
		DetourAttach(&(PVOID&)VirtualAlloc_				, HookedVirtualAlloc);
		DetourAttach(&(PVOID&)VirtualAllocEx_			, HookedVirtualAllocEx);
		DetourAttach(&(PVOID&)VirtualProtect_			, HookedVirtualProtect);
		DetourAttach(&(PVOID&)VirtualProtectEx_			, HookedVirtualProtectEx);
		DetourAttach(&(PVOID&)MapViewOfFile_			, HookedMapViewOfFile);
		DetourAttach(&(PVOID&)MapViewOfFileEx_			, HookedMapViewOfFileEx);
		DetourAttach(&(PVOID&)HeapCreate_				, HookedHeapCreate);
		DetourAttach(&(PVOID&)SetProcessDEPPolicy_		, HookedSetProcessDEPPolicy);
		DetourAttach(&(PVOID&)NtSetInformationProcess_	, HookedNtSetInformationProcess);
		DetourAttach(&(PVOID&)WriteProcessMemory_		, HookedWriteProcessMemory);
		DetourAttach(&(PVOID&)LdrHotPatchRoutine_		, HookedLdrHotPatchRoutine);		
	}

    /* Hook CreateThread if ETA_VALIDATION protection is set on */
	if ( PWNYPOT_REGCONFIG.SHELLCODE.ETA_VALIDATION )
	{
		DetourAttach(&(PVOID&)CreateThread_				, HookedCreateThread);
	}

    /* Hook function we need for loging shellcode activity */
	if ( PWNYPOT_REGCONFIG.SHELLCODE.ANALYSIS_SHELLCODE )
	{
		DetourAttach(&(PVOID&)URLDownloadToFileW_		, HookedURLDownloadToFileW);
		DetourAttach(&(PVOID&)socket_					, Hookedsocket);
		DetourAttach(&(PVOID&)connect_					, Hookedconnect);
		DetourAttach(&(PVOID&)listen_					, Hookedlisten);
		DetourAttach(&(PVOID&)bind_						, Hookedbind);
		DetourAttach(&(PVOID&)accept_					, Hookedaccept);
		DetourAttach(&(PVOID&)send_						, Hookedsend);
		DetourAttach(&(PVOID&)recv_						, Hookedrecv);
	}

    error = DetourTransactionCommit();
    if (error == NO_ERROR)
	{
		TrueSocket = socket_;
		TrueConnect = connect_;
		TrueSend = send_;
		PWNYPOT_REGCONFIG.PROCESS_HOOKED = TRUE;
		return PWNYPOT_STATUS_SUCCESS;
	}
	else
	{
		return PWNYPOT_STATUS_GENERAL_FAIL;
	}
}

STATUS
HookUninstall(
	VOID
	)
{
	DEBUG_PRINTF(LDBG,NULL,"Uninstalling Hooks\n");
	CreateProcessInternalW_ = (BOOL (WINAPI *)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE))GetProcAddress(GetModuleHandle("KERNEL32.DLL"), "CreateProcessInternalW");
	NtSetInformationProcess_ = (t_NtSetInformationProcess)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtSetInformationProcess"));
	LdrHotPatchRoutine_ = (t_LdrHotPatchRoutine)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "LdrHotPatchRoutine"));
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	/* Unhooking functions */
	DetourDetach(&(PVOID&)CreateProcessInternalW_		, HookedCreateProcessInternalW);

	if ( PWNYPOT_REGCONFIG.ROP.DETECT_ROP )
	{
		DetourDetach(&(PVOID&)VirtualAlloc_				, HookedVirtualAlloc);
		DetourDetach(&(PVOID&)VirtualAllocEx_			, HookedVirtualAllocEx);
		DetourDetach(&(PVOID&)VirtualProtect_			, HookedVirtualProtect);
		DetourDetach(&(PVOID&)VirtualProtectEx_			, HookedVirtualProtectEx);
		DetourDetach(&(PVOID&)MapViewOfFile_			, HookedMapViewOfFile);
		DetourDetach(&(PVOID&)MapViewOfFileEx_			, HookedMapViewOfFileEx);
		DetourDetach(&(PVOID&)HeapCreate_				, HookedHeapCreate);
		DetourDetach(&(PVOID&)SetProcessDEPPolicy_		, HookedSetProcessDEPPolicy);	
		DetourDetach(&(PVOID&)WriteProcessMemory_		, HookedWriteProcessMemory);	
		DetourDetach(&(PVOID&)NtSetInformationProcess_	, HookedNtSetInformationProcess);
		DetourDetach(&(PVOID&)LdrHotPatchRoutine_		, HookedLdrHotPatchRoutine);
	}

	if ( PWNYPOT_REGCONFIG.SHELLCODE.ETA_VALIDATION )
	{
		DetourDetach(&(PVOID&)CreateThread_				, HookedCreateThread);
	}

	if ( PWNYPOT_REGCONFIG.SHELLCODE.ANALYSIS_SHELLCODE )
	{
		DetourDetach(&(PVOID&)CreateThread_				, HookedCreateThread);
		DetourDetach(&(PVOID&)URLDownloadToFileW_		, HookedURLDownloadToFileW);
		DetourDetach(&(PVOID&)socket_					, Hookedsocket);
		DetourDetach(&(PVOID&)connect_					, Hookedconnect);
		DetourDetach(&(PVOID&)listen_					, Hookedlisten);
		DetourDetach(&(PVOID&)bind_						, Hookedbind);
		DetourDetach(&(PVOID&)accept_					, Hookedaccept);
		DetourDetach(&(PVOID&)send_						, Hookedsend);
		DetourDetach(&(PVOID&)recv_						, Hookedrecv);
	}

	DetourTransactionCommit();
	return PWNYPOT_STATUS_SUCCESS;
}


HANDLE 
WINAPI 
HookedCreateThread(
	LPSECURITY_ATTRIBUTES lpThreadAttributes, 
	SIZE_T dwStackSize, 
	LPTHREAD_START_ROUTINE lpStartAddress, 
	LPVOID lpParameter, 
	DWORD dwCreationFlags, 
	LPDWORD lpThreadId
	)
 {
	 HANDLE	hThreadHandle;
	 DWORD dwThreadId;
	 PHWBREAKDATA phd;


	 /* Enable breakpoint for new thread only when shellcode is not detected */
	 if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_NOT_SET )
	 {
		 phd					= (PHWBREAKDATA)LocalAlloc(LMEM_ZEROINIT, sizeof(HWBREAKDATA));
		 phd->Address			= PeGetExportDirectoryRVAddress(GetModuleHandle(PWNYPOT_REGCONFIG.SHELLCODE.ETA_MODULE));
		 phd->dwCondition		= HW_ACCESS;				/* Breakpoint type */
		 phd->dwSize			= 4;						/* Breakpoint size */
		 phd->dwThreadStatus	= THREAD_ALREADY_SUSPEND;	/* this means BreakSetup() does't need to suspend thread */

		 /* check bit 2 if is set we have CREATE_SUSPENDED in dwCreationFlags */
		 if ( IsBitSet( dwCreationFlags, 2 ) )  
		 {
			 /* create thread with original dwCreationFlags because it already has CREATE_SUSPENDED bit set! */
			 hThreadHandle = CreateThread_(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, &dwThreadId);

			 if ( lpThreadId != NULL)
				 *lpThreadId = dwThreadId;

			 /* set Thread ID in HWINFO struct and then call BreakSetup() to setup break points for newly created thread */
			 phd->dwThreadId = dwThreadId;
			 DbgThreadSetBreakpoint(phd);

			 if ( phd->dwStatus == DR_ALL_BUSY )
				DEBUG_PRINTF(LDBG, NULL, "All Debug Registers for TID (%p) are busy!\n", dwThreadId);
			 else if ( phd->dwStatus == DR_BREAK_ERROR_UNK )
				DEBUG_PRINTF(LDBG, NULL, "Internal error occurred during TID (%p) DR setting process!\n", dwThreadId);
			 LocalFree(phd);

		 } else 
		 {
			 /* thread is not created in suspend state by default, so we just set the suspend thread bit and call the original CreateThread! */
			 hThreadHandle = CreateThread_(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags | CREATE_SUSPENDED, &dwThreadId);
		 
			 if ( lpThreadId != NULL)
				 *lpThreadId = dwThreadId;

			 phd->dwThreadId = dwThreadId;
			 DbgThreadSetBreakpoint(phd);

			 if ( phd->dwStatus == DR_ALL_BUSY )
				 DEBUG_PRINTF(LDBG, NULL, "All Debug Registers for TID (%p) are busy!\n", dwThreadId);
			 else if ( phd->dwStatus == DR_BREAK_ERROR_UNK )
				 DEBUG_PRINTF(LDBG, NULL, "Internal error occurred during TID (%p) DR setting process!\n", dwThreadId);

			 /* resume the thread only if it's not created in suspended state by default! */
			 ResumeThread(hThreadHandle);
			 LocalFree(phd);
		 }

		 /* return the thread handler! */
		 return hThreadHandle;
	 }

	 /* shellcode detected, just call the original function */
	 return (CreateThread_(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId));
 }

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
	)
{
	BOOL bReturn;
#ifndef CUCKOO
	CHAR szDllFullPath[MAX_PATH];
#endif
	/* apply config rules if shellcode or ROP detected */
	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET || DbgGetRopFlag() == PWNYPOT_STATUS_ROP_FLAG_SET )
	{
		PXMLNODE XmlIDLogNode;
		if ( PWNYPOT_REGCONFIG.SHELLCODE.ANALYSIS_SHELLCODE )
		{
			CHAR *szApplicationNameA = (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);
			CHAR *szCommandLineA     = (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);

			if ( lpApplicationName != NULL )
				wcstombs( szApplicationNameA, lpApplicationName, 1024);

			if ( lpCommandLine != NULL )
				wcstombs( szCommandLineA, lpCommandLine, 1024);

			XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
			/* type */
			mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_EXEC);
			mxmlElementSetAttr(XmlIDLogNode, "exec_process", szApplicationNameA);
			mxmlElementSetAttr(XmlIDLogNode, "exec_cmd", szCommandLineA);
			/* save */

			LocalFree(szApplicationNameA);
			LocalFree(szCommandLineA);
		}

        /* if malware execution is not allowd then terminate the process */
		if ( PWNYPOT_REGCONFIG.GENERAL.ALLOW_MALWARE_EXEC == FALSE )
		{
			SaveXml( XmlLog );
			TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_VIOLATION);
		}

        /* let the malware execute */
        BOOL res = (CreateProcessInternalW_( hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken));
 
 #ifdef CUCKOO
			CHAR *pid     = (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);        	
        	sprintf(pid, "%d", lpProcessInformation->dwProcessId);
			mxmlElementSetAttr(XmlIDLogNode, "exec_pid", pid);
			SaveXml( XmlLog );
			DEBUG_PRINTF(LDBG, NULL, "Executing Malware with cuckoomon.dll: %d\n", lpProcessInformation->dwProcessId);
			char buf[MAX_PATH];
			sprintf(buf,"PROCESS:%d,cuckoomon.dll",lpProcessInformation->dwProcessId,MAX_PATH);
			pipe(buf);

#endif		       
		return res;
	}
	/* if the process is creating with CREATE_SUSPENDED flag, let it do its job */
	if ( IsBitSet(dwCreationFlags, 2) )
	{
		bReturn = CreateProcessInternalW_( hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);

		if ( bReturn != FALSE )
		{
           
#ifndef CUCKOO	
			strncpy( szDllFullPath, PWNYPOT_REGCONFIG.PWNYPOT_MODULE_PATH, MAX_PATH );
			if ( InjectDLLIntoProcess( szDllFullPath, lpProcessInformation->hProcess ) != PWNYPOT_STATUS_SUCCESS )
			{
				DEBUG_PRINTF(LDBG, NULL, "Module failed to inject itself into newly created process , PID : %d\n", lpProcessInformation->dwProcessId);
				return bReturn;
			}

			DEBUG_PRINTF(LDBG, NULL, "Module injected itself into newly created process , PID : %d\n", lpProcessInformation->dwProcessId);
			/* Sleep for INIT_WAIT_TIME sec and let PwnyPot init itself in newly created process
			   TODO : use a messaging mechanism and resume process after init finished instead of sleeping! */
			
#else
			DEBUG_PRINTF(LDBG, NULL, "New Process with CREATE_SUSPENDED: %d\n", lpProcessInformation->dwProcessId);
			char buf[MAX_PATH];
			sprintf(buf,"PROCESS:%d,PwnyPot.dll",lpProcessInformation->dwProcessId,MAX_PATH);
			pipe(buf);

#endif			
			Sleep(INIT_WAIT_TIME);
			return bReturn;
		}
	} 
	else
	{
		/* if the process is not creating with CREATE_SUSPENDED flag, force it do it */
		bReturn = CreateProcessInternalW_( hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags | CREATE_SUSPENDED , lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
		
		if ( bReturn != FALSE )
		{
#ifndef CUCKOO			
             /* TODO : We dont need this if ther process is already added into Protection List in registry, so we should remove this lines  */
			strncpy( szDllFullPath, PWNYPOT_REGCONFIG.PWNYPOT_MODULE_PATH, MAX_PATH );
			if ( InjectDLLIntoProcess( szDllFullPath, lpProcessInformation->hProcess ) != PWNYPOT_STATUS_SUCCESS )
			{
				DEBUG_PRINTF(LDBG, NULL, "Module failed to inject itself into newly created process , PID : %d\n", lpProcessInformation->dwProcessId);
				ResumeThread(lpProcessInformation->hThread);
				return bReturn;
			}

			DEBUG_PRINTF(LDBG, NULL, "Module injected itself into newly created process , PID : %d\n", lpProcessInformation->dwProcessId);
#else
			DEBUG_PRINTF(LDBG, NULL, "New Process !without! CREATE_SUSPENDED: %d\n", lpProcessInformation->dwProcessId);
			char buf[MAX_PATH];
			sprintf(buf,"PROCESS:%d,PwnyPot.dll",lpProcessInformation->dwProcessId,MAX_PATH);
			DWORD len = strlen(buf);
			pipe(buf);
#endif				
			/* Sleep for INIT_WAIT_TIME sec and let PwnyPot init itself in newly created process
			   TODO : use a messaging mechanism and resume process after init finished instead of sleeping! */
			Sleep(INIT_WAIT_TIME);
			ResumeThread(lpProcessInformation->hThread);
			return bReturn;
		}
	}
	
	return bReturn;
}


HRESULT
WINAPI
HookedURLDownloadToFileW(
    LPUNKNOWN pCaller,
    LPCWSTR szURL,
    LPCWSTR szFileName,
    DWORD dwReserved,
    LPBINDSTATUSCALLBACK lpfnCB
	)
{
	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET )
	{
		CHAR *szUrlA			= (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);
		CHAR *szFileNameA		= (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);
		PXMLNODE XmlIDLogNode;

		if ( szURL != NULL )
			wcstombs( szUrlA, szURL, 1024);

		if ( szFileName != NULL )
			wcstombs( szFileNameA, szFileName, 1024);

		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		/* type */
		mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_DL2FILE);
		mxmlElementSetAttr(XmlIDLogNode, "download_url", (PCHAR)szUrlA);
		mxmlElementSetAttr(XmlIDLogNode, "download_filename", (PCHAR)szFileNameA);
		/* save */
		SaveXml( XmlLog );

		if ( PWNYPOT_REGCONFIG.SHELLCODE.ALLOW_MALWARE_DOWNLOAD == FALSE )
			return S_OK;

		LocalFree(szUrlA);
		LocalFree(szFileNameA);
	}

	return (URLDownloadToFileW_( pCaller, szURL, szFileName, dwReserved, lpfnCB));
}

HMODULE 
WINAPI
HookedLoadLibraryExW(
	LPCWSTR lpLibFileName, 
	HANDLE hFile, 
	DWORD dwFlags
	)
{
	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET )
	{
		CHAR *szLibFileNameA = (CHAR *)LocalAlloc(LMEM_ZEROINIT, 1024);
		PXMLNODE XmlLogNode;
		PXMLNODE XmlDataNode;

		if ( lpLibFileName != NULL )
			wcstombs( szLibFileNameA, lpLibFileName, 1024);

		XmlLogNode = CreateXmlElement( XmlShellcode, "loadlib");
		XmlDataNode = CreateXmlElement( XmlLogNode, "libname");
		SetTextNode( XmlDataNode, 0, szLibFileNameA);
		SaveXml( XmlLog );

		LocalFree(szLibFileNameA);
	}

	return (LoadLibraryExW_( lpLibFileName, hFile, dwFlags));
}

SOCKET
WSAAPI
Hookedsocket(
	int af,
	int type,
	int protocol
	)
{
	int ret_val;

	ret_val = (socket_( af, type, protocol));
	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlIDLogNode;

		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_SOCKET);
		mxmlElementSetAttrf(XmlIDLogNode, "socket", "%d", ret_val);
		// socket
		switch (af) 
		{
		case AF_UNSPEC:
			mxmlElementSetAttr( XmlIDLogNode, "AF", "Unspecified");
				break;
		case AF_INET:
			mxmlElementSetAttr( XmlIDLogNode, "AF", "AF_INET (IPv4)");
			break;
		case AF_INET6:
			mxmlElementSetAttr( XmlIDLogNode, "AF", "AF_INET6 (IPv6)");
			break;
		case AF_NETBIOS:
			mxmlElementSetAttr( XmlIDLogNode, "AF", "AF_NETBIOS (NetBIOS)");
			break;
		case AF_BTH:
			mxmlElementSetAttr( XmlIDLogNode, "AF", "AF_BTH (Bluetooth)");
			break;
		default:
			mxmlElementSetAttr( XmlIDLogNode, "AF", "Other");
			break;
		}

		switch (type) 
		{
		case 0:
			mxmlElementSetAttr( XmlIDLogNode, "socket_type", "Unspecified");
			break;
		case SOCK_STREAM:
			mxmlElementSetAttr( XmlIDLogNode, "socket_type", "SOCK_STREAM (stream)");
			break;
		case SOCK_DGRAM:
			mxmlElementSetAttr( XmlIDLogNode, "socket_type", "SOCK_DGRAM (datagram)");
			break;
		case SOCK_RAW:
			mxmlElementSetAttr( XmlIDLogNode, "socket_type", "SOCK_RAW (raw)");
			break;
		case SOCK_RDM:
			mxmlElementSetAttr( XmlIDLogNode, "socket_type", "SOCK_RDM (reliable message datagram)");
			break;
		case SOCK_SEQPACKET:
			mxmlElementSetAttr( XmlIDLogNode, "socket_type", "SOCK_SEQPACKET (pseudo-stream packet)");
			break;
		default:
			mxmlElementSetAttr( XmlIDLogNode, "socket_type", "Other");
			break;
		}

		switch (protocol)
		{
		case 0:
			mxmlElementSetAttr( XmlIDLogNode, "socket_protocol", "Unspecified");
			break;
		case IPPROTO_ICMP:
			mxmlElementSetAttr( XmlIDLogNode, "socket_protocol", "IPPROTO_ICMP (ICMP)");
			break;
		case IPPROTO_IGMP:
			mxmlElementSetAttr( XmlIDLogNode, "socket_protocol", "IPPROTO_IGMP (IGMP)");
			break;
		case IPPROTO_TCP:
			mxmlElementSetAttr( XmlIDLogNode, "socket_protocol", "IPPROTO_TCP (TCP)");
			break;
		case IPPROTO_UDP:
			mxmlElementSetAttr( XmlIDLogNode, "socket_protocol", "IPPROTO_UDP (UDP)");
			break;
		case IPPROTO_ICMPV6:
			mxmlElementSetAttr( XmlIDLogNode, "socket_protocol", "IPPROTO_ICMPV6 (ICMP Version 6)");
			break;
		default:
			mxmlElementSetAttr( XmlIDLogNode, "socket_protocol", "Other");
			break;
		}
		// save
		SaveXml( XmlLog );
	}
	return ret_val;
}


int
WSAAPI
Hookedconnect(
	SOCKET s,
    const struct sockaddr *name,
	int namelen
    )
{
	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlIDLogNode;
		CHAR szPort[20];
		sockaddr_in *sdata;
		sdata = (sockaddr_in *)name;
		
		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_CONNECT);
		// connect
		mxmlElementSetAttrf(XmlIDLogNode, "socket", "%d", s);
		mxmlElementSetAttr( XmlIDLogNode, "connect_ip", inet_ntoa(sdata->sin_addr));
		mxmlElementSetAttr( XmlIDLogNode, "connect_port", _itoa(htons(sdata->sin_port), szPort, 10));

		// save
		SaveXml( XmlLog );
	}

	return (connect_(s, name, namelen));
}


int
WSAAPI
Hookedlisten(
	SOCKET s,
	int backlog
	)
{
	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlIDLogNode;
		PXMLNODE XmlLogNode;

		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_LISTEN);
		// listen
		mxmlElementSetAttrf(XmlIDLogNode, "socket", "%d", s);
		XmlLogNode = mxmlNewElement( XmlIDLogNode, "listen_desc");
		mxmlNewText( XmlLogNode, 0, "Shellcode attemp to listen on a port (possibly on previously bind address).");
		// save
		SaveXml( XmlLog );
	}

	return (listen_( s,backlog ));
}


int
WSAAPI
Hookedbind(
  SOCKET s,
  const struct sockaddr *name,
  int namelen
  )
{
	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlIDLogNode;
		CHAR szPort[20];
		sockaddr_in *sdata;
		sdata = (sockaddr_in *)name;

		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_BIND);
		mxmlElementSetAttrf(XmlIDLogNode, "socket", "%d", s);
		mxmlElementSetAttr(XmlIDLogNode, "bind_ip", inet_ntoa(sdata->sin_addr));
		mxmlElementSetAttr(XmlIDLogNode, "bind_port", _itoa(htons(sdata->sin_port),szPort, 10));
		// save
		SaveXml( XmlLog );
	}

	return (bind_(s, name, namelen));
}

SOCKET
WSAAPI
Hookedaccept(
	SOCKET s,
	struct sockaddr *addr,
	int *addrlen
	)
{

	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET )
	{
		PXMLNODE XmlIDLogNode;
		CHAR szPort[20];
		sockaddr_in *sdata;
		sdata = (sockaddr_in *)addr;
		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_ACCEPT);

		if ( addr != NULL && addrlen != NULL )
		{
			mxmlElementSetAttrf(XmlIDLogNode, "socket", "%d", s);
			mxmlElementSetAttr(XmlIDLogNode, "accept_ip", inet_ntoa(sdata->sin_addr));
			mxmlElementSetAttr(XmlIDLogNode, "accept_port", _itoa(htons(sdata->sin_port),szPort, 10));
		}
		else
		{
			mxmlElementSetAttr(XmlIDLogNode, "accept_ip", "NULL");
			mxmlElementSetAttr(XmlIDLogNode, "accept_port", "NULL");
		}
		// save
		SaveXml( XmlLog );
	}


	return (accept_( s, addr, addrlen ));
}

int
WSAAPI
Hookedsend(
	SOCKET s,
	const char *buf,
	int len,
	int flags
	)
{
	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET )
	{
		CHAR szPort[20];
        CHAR szUID[UID_SIZE];
		sockaddr_in sdata;
		PXMLNODE XmlIDLogNode;
		int sock_len = sizeof(sockaddr);

		if ( len > 1 )
		{
			XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
			// type
			mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_SEND);
			getpeername( s, (sockaddr *)&sdata, &sock_len);
			mxmlElementSetAttrf(XmlIDLogNode, "socket", "%d", s);
			mxmlElementSetAttr(XmlIDLogNode, "send_ip", inet_ntoa(sdata.sin_addr));
			mxmlElementSetAttr(XmlIDLogNode, "send_port", _itoa(htons(sdata.sin_port), szPort, 10));
			mxmlElementSetAttr(XmlIDLogNode, "send_datalen", _itoa(len, szPort, 10));
			mxmlElementSetAttr(XmlIDLogNode, "data_uid", GenRandomStr(szUID, UID_SIZE-1));
            HexDumpToFile((PBYTE)buf, len ,szUID);
			// save
			SaveXml( XmlLog );
		}
	}

	return (send_( s, buf, len, flags));
}

int
WSAAPI
Hookedrecv(
	SOCKET s,
	char *buf,
	int len,
	int flags
	)
{

	if ( DbgGetShellcodeFlag() == PWNYPOT_STATUS_SHELLCODE_FLAG_SET && len > 1)
	{
		CHAR szPort[20];
        CHAR szUID[UID_SIZE];
		sockaddr_in sdata;
		int sock_len = sizeof(sockaddr);
		PXMLNODE XmlIDLogNode;
			
		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		// type
		mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_RECV);
		getpeername( s, (sockaddr *)&sdata, &sock_len);
		mxmlElementSetAttrf(XmlIDLogNode, "socket", "%d", s);
		mxmlElementSetAttr(XmlIDLogNode, "recv_ip", inet_ntoa(sdata.sin_addr));
		mxmlElementSetAttr(XmlIDLogNode, "recv_port", _itoa(htons(sdata.sin_port), szPort, 10));
		mxmlElementSetAttr(XmlIDLogNode, "recv_datalen", _itoa(len, szPort, 10));
		mxmlElementSetAttr(XmlIDLogNode, "data_uid", GenRandomStr(szUID, UID_SIZE-1));
        HexDumpToFile((PBYTE)buf, len ,szUID);
		// save
		SaveXml( XmlLog );
	}

	return (recv_( s, buf, len, flags));
}

BOOL
WINAPI
HookedSetProcessDEPPolicy(
	DWORD dwFlags
	)
{
	PXMLNODE XmlIDLogNode;
	XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
	mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_API);
	mxmlElementSetAttr(XmlIDLogNode, "api", "SetProcessDEPPolicy");
	mxmlElementSetAttrf(XmlIDLogNode, "value", "%d", dwFlags);
	if (PWNYPOT_REGCONFIG.GENERAL.ALLOW_MALWARE_EXEC) 
	{
		SaveXml( XmlLog );
		return SetProcessDEPPolicy_(dwFlags);
	}
	else 
	{	
		if (dwFlags == 0)
		{
			DEBUG_PRINTF(LSHL, NULL, "Stopping Process because it was trying to disable DEP.\n");
			SaveXml( XmlLog );
			TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_VIOLATION);
		}
	}
	return 0;
}

NTSTATUS
WINAPI
HookedNtSetInformationProcess(
	HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength 
    )
{
	if (ProcessInformationClass == ProcessExecuteFlags){
		PXMLNODE XmlIDLogNode;
		XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
		mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_API);
		mxmlElementSetAttr(XmlIDLogNode, "api", "NtSetInformationProcess");
		mxmlElementSetAttrf(XmlIDLogNode, "value", "0x%p", (*(ULONG_PTR *)ProcessInformation));
		SaveXml( XmlLog );
		if (PWNYPOT_REGCONFIG.GENERAL.ALLOW_MALWARE_EXEC) 
		{
			DEBUG_PRINTF(LSHL, NULL, "HookedNtSetInformationProcess is called with ProcessExecuteFlags value: %p.\n", (*(ULONG_PTR *)ProcessInformation) );
			return NtSetInformationProcess_(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
		}
		else 
		{				 
			if (((*(ULONG_PTR *)ProcessInformation) & MEM_EXECUTE_OPTION_ENABLE) == 0x2 )
			{
				DEBUG_PRINTF(LSHL, NULL, "Stopping Process because it was trying to disable DEP.\n");
				TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_VIOLATION);
			}
		}
	}
	return 0;
}

VOID 
NTAPI
HookedLdrHotPatchRoutine(
	HotPatchBuffer * s_HotPatchBuffer
	)
{
	DEBUG_PRINTF(LSHL, NULL, "HookedLdrHotPatchRoutine called.\n");
	PXMLNODE XmlIDLogNode;
	XmlIDLogNode = mxmlNewElement( XmlShellcode, "row");
	mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_API);
	mxmlElementSetAttr(XmlIDLogNode, "api", "LdrHotPatchRoutine");
	mxmlElementSetAttrf(XmlIDLogNode, "value", "%ls,%ls", s_HotPatchBuffer->PatcherName,  s_HotPatchBuffer->PatcheeName);
	if (PWNYPOT_REGCONFIG.SHELLCODE.ALLOW_MALWARE_DOWNLOAD)
	{
		//mxmlElementSetAttr(XmlIDLogNode, "downloaded_dll", "1");
		SaveXml( XmlLog );
		LdrHotPatchRoutine_(s_HotPatchBuffer);
	}
	else {
		//mxmlElementSetAttr(XmlIDLogNode, "downloaded_dll", "0");
		SaveXml( XmlLog );
		DEBUG_PRINTF(LSHL, NULL, "Denied downloading of library because of ALLOW_MALWARE_DOWNLOAD=0");
	}
	
}
