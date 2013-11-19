/*
    PwnyPot is a Client side High Interaction Honeypot
    Developed by  Shahriyar Jalayeri ( Shahriyar.j {at} gmail {dot}  com )
    www.irhoneynet.org
    twitter.com/ponez
*/
#pragma once
#include "Hook.h"
#include "ParseConfig.h"
#include "LogInfo.h"
#include "ETAV_DebugBreak.h"
#include "GeneralProtections.h"
#include "SEHOP.h"
#include "Hash.h"
#include <Psapi.h>
#include <stdlib.h>
#pragma comment(lib, "Psapi.lib")

PWNYPOTREGCONFIG PWNYPOT_REGCONFIG;
extern PXMLNODE XmlLog;
extern PXMLNODE XmlShellcode;
extern int (WSAAPI *TrueConnect		 )( SOCKET s, const struct sockaddr *name, int namelen ) ;
extern SOCKET (WSAAPI *TrueSocket    )( int af, int type, int protocol );
extern     int (WSAAPI *TrueSend   )( SOCKET s, const char *buf, int len, int flags );

STATUS
SetupShellcodeDetector(
	VOID
	);

BOOL
APIENTRY
DllMain( 
	HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
	)
{
#ifdef _DEBUG
	BOOL infinity = TRUE;
	while(infinity)
	{
		
	}
#endif
	BYTE AppFullNameHash[MAX_HASH_SIZE];
#ifndef CUCKOO	
	CHAR szAppFullNameHash[MAX_PATH];
#endif 
	CHAR szAppFullName[MAX_PATH];
	DWORD dwAppFullNameHashValueSize = MAX_HASH_SIZE;
	HANDLE hDetectorThread;
	ERRORINFO err;
	if ( ul_reason_for_call == DLL_PROCESS_ATTACH )
	{

		/* get module full name, we need it for initializing config */
		if ( !GetModuleFileName( NULL, szAppFullName, MAX_PATH ) )
		{
			DEBUG_PRINTF(LDBG, NULL, "GetModuleBaseName() failed!\n");
			return FALSE; /* PWNYPOT_STATUS_INTERNAL_ERROR */
		}

		if ( GetSHA1Hash( (PBYTE)strtolow(szAppFullName), strlen(szAppFullName), AppFullNameHash, &dwAppFullNameHashValueSize ) != PWNYPOT_STATUS_SUCCESS )
		{
			DEBUG_PRINTF(LDBG, NULL, "GetSHA1Hash() failed!\n");
			return FALSE; /* PWNYPOT_STATUS_INTERNAL_ERROR */
		}

		/* read and parse the config from registry */
#ifndef CUCKOO		
		if ( ParseRegConfig( &PWNYPOT_REGCONFIG, HashToStr( AppFullNameHash, dwAppFullNameHashValueSize, szAppFullNameHash, MAX_PATH) , MAX_MODULE_NAME32 ) != PWNYPOT_STATUS_SUCCESS )
#else 
		if ( ParseConfig( &PWNYPOT_REGCONFIG) != PWNYPOT_STATUS_SUCCESS )
#endif
		{
			REPORT_ERROR("ParseRegConfig()", &err);
			return FALSE; /* PWNYPOT_STATUS_INTERNAL_ERROR */
		}

#ifdef CUCKOO
		if ( InitCuckooLogs() != PWNYPOT_STATUS_SUCCESS ) {
			REPORT_ERROR("InitCuckooLogs()", &err);
			return FALSE;
		}		
#endif

#ifndef CUCKOO
		/* only init targeted process otherwise unload DLL from process address space. */
		if ( _stricmp(szAppFullName, PWNYPOT_REGCONFIG.APP_PATH ) )
		{
			return FALSE;
		}
#endif
		hDetectorThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)SetupShellcodeDetector, NULL, 0, NULL);
		if ( hDetectorThread != NULL )
		{
			DEBUG_PRINTF(LDBG, NULL, "Shellcode Detector thread started!\n");
		}
	} 
	else if ( ul_reason_for_call == DLL_PROCESS_DETACH )
	{		
		/* Disable Export Table Address Filtering for all running threads. */
		/*
		if ( DbgDisableExportAddressFiltering() != PWNYPOT_STATUS_SUCCESS )
		{
			DEBUG_PRINTF(LDBG, NULL, "EAF failed to disable protection...\n");
		}
		*/

		/* unhook functions */
		if ( PWNYPOT_REGCONFIG.PROCESS_HOOKED )
			HookUninstall();
	}
	return TRUE;
}

STATUS
SetupShellcodeDetector(
	VOID
	)
{
	ERRORINFO err;
	/* creating XML */
	XmlLog = NewXmlRoot("1.0");
	XmlShellcode = CreateXmlElement(XmlLog, "shellcode");

	/* check if we should delay the protection init */
	if ( PWNYPOT_REGCONFIG.INIT_DELAY > 0 )
	{
		/* Sleep for INIT_DELAY seconds */
		Sleep(PWNYPOT_REGCONFIG.INIT_DELAY * SEC );
	}

	/* init log path 
	if ( InitLogPath( PWNYPOT_REGCONFIG.LOG_PATH, MAX_PATH ) != PWNYPOT_STATUS_SUCCESS )
	{
		REPORT_ERROR("InitLogPath()", &err);
		return PWNYPOT_STATUS_GENERAL_FAIL;
	}
    */


	/* enable SEHOP for this process? */
	if ( PWNYPOT_REGCONFIG.GENERAL.SEHOP )
	{
		if ( EnableSEHOP() != PWNYPOT_STATUS_SUCCESS )
		{
			DEBUG_PRINTF(LDBG, NULL, "Error occured in EnableSEHOP()\n");
			return PWNYPOT_STATUS_GENERAL_FAIL;
		}
		DEBUG_PRINTF(LDBG, NULL, "SEHOP enabled for this process.\n");
	}

	/* check if we should enable NULL Page Allocation Prevention mitigation  */
	if ( PWNYPOT_REGCONFIG.GENERAL.NULL_PAGE )
	{
		if ( EnableNullPageProtection() != PWNYPOT_STATUS_SUCCESS )
		{
			REPORT_ERROR("EnableNullPageProtection()", &err);
			return PWNYPOT_STATUS_GENERAL_FAIL;
		}
	}

	/* check if we should enable Heap Spray Prevention mitigation  */
	if ( PWNYPOT_REGCONFIG.GENERAL.HEAP_SPRAY )
	{
		if ( EnableHeapSprayProtection(PWNYPOT_REGCONFIG.GENERAL.HEAP_SPRAY_ADDRESSES) != PWNYPOT_STATUS_SUCCESS )
		{
			REPORT_ERROR("EnableHeapSprayProtection()", &err);
			return PWNYPOT_STATUS_GENERAL_FAIL;
		}
	}

	/* if Export Table Access Vaidation is enable then activate it! */
	if ( PWNYPOT_REGCONFIG.SHELLCODE.ETA_VALIDATION )
	{
		/* add exception handler for handling break points */
		if ( !AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)DbgExceptionHandler) )
		{
			REPORT_ERROR("AddVectoredExceptionHandler()", &err);
			return PWNYPOT_STATUS_INTERNAL_ERROR;
		}
		
		/* log current loaded modules */
		if ( LdrLoadListEntry() != PWNYPOT_STATUS_SUCCESS )
		{
			DEBUG_PRINTF(LDBG, NULL, "ListProcessModules() faild!\n");
			return PWNYPOT_STATUS_GENERAL_FAIL;
		}

		/* enable ETA validation for all current running threads */
		if ( DbgEnableExportAddressFiltering() != PWNYPOT_STATUS_SUCCESS)
		{
			DEBUG_PRINTF(LDBG, NULL, "Error occured in DbgEnableExportAddressFiltering()");
			if ( !PWNYPOT_REGCONFIG.SKIP_HBP_ERROR )
				return PWNYPOT_STATUS_GENERAL_FAIL;
		}
	}

	/* hook functions! */
	if ( HookInstall() != PWNYPOT_STATUS_SUCCESS )
	{
		DEBUG_PRINTF(LDBG, NULL, "Error in Hooking process!\n");
		return PWNYPOT_STATUS_GENERAL_FAIL;
	}

	/* check if we should enable Permanent DEP mitigation */
	if ( PWNYPOT_REGCONFIG.GENERAL.PERMANENT_DEP )
	{
		if ( EnablePermanentDep() != PWNYPOT_STATUS_SUCCESS )
		{
			REPORT_ERROR("EnablePermanentDep()", &err);
#ifndef CUCKOO			
			return PWNYPOT_STATUS_GENERAL_FAIL;
#endif
		}
	}

	DEBUG_PRINTF(LDBG, NULL, "Functions hooked successfully!\n");
	return PWNYPOT_STATUS_SUCCESS;
}