#include "RopDetection.h"

BOOL bRopDetected = FALSE;
BOOL bRopLoged = FALSE;

extern "C"
VOID
ValidateCallAgainstRop(
	IN ULONG_PTR lpEspAddress,
	IN ROP_CALLEE RopCallee,
	IN LPVOID lpAddress, 
	IN DWORD flProtect
	)
{
	PNT_TIB ThreadInfo;
	
	if ( DbgGetRopFlag() == PWNYPOT_STATUS_ROP_FLAG_NOT_SET )
	{
		/* get the thread stack range from TIB. */
		ThreadInfo = (PNT_TIB) __readfsdword( 0x18 );

		/* monitor esp value if we supposed to */
		if ( PWNYPOT_REGCONFIG.ROP.STACK_MONITOR )
		{
			/* check if thread is passing the actual stack boundaries */
			if ( lpEspAddress < (DWORD)ThreadInfo->StackLimit || lpEspAddress >= (DWORD)ThreadInfo->StackBase ) 
			{
				/* set ROP flags */
				DbgSetRopFlag();
				DEBUG_PRINTF(LROP,NULL,"ROP Detected by STACK_MONITOR, out of bound stack!\n");
			}
		}

		/* Monitor stack page permission change value if we supposed to */
		if ( PWNYPOT_REGCONFIG.MEM.STACK_RWX )
		{
			if ( lpAddress > ThreadInfo->StackLimit || lpAddress <= ThreadInfo->StackBase )
			{
				/* if it is going to make the stack executable */
				if ( ( flProtect & PAGE_EXECUTE )           ||  
					 ( flProtect & PAGE_EXECUTE_READWRITE ) || 
					 ( flProtect & PAGE_EXECUTE_READ )      ||
					 ( flProtect & PAGE_EXECUTE_WRITECOPY ) )
				{
#ifdef CUCKOO					
					CHAR szAssciFullModuleName[MAX_MODULE_NAME32];
					DbgGetRopModule( (PVOID)lpEspAddress, szAssciFullModuleName, MAX_MODULE_NAME32);
					if (strncmp(szAssciFullModuleName, PWNYPOT_REGCONFIG.DLL_PATH, MAX_MODULE_NAME32)!=0) 
					{
#endif 
						DbgSetRopFlag();
						DEBUG_PRINTF(LROP,NULL,"ROP Detected by STACK_RWX, stack permission changed to be executable!\n");

#ifdef CUCKOO					
					} 
#endif 
				}
			}
		}

		if ( PWNYPOT_REGCONFIG.ROP.PIVOT_DETECTION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( PWNYPOT_REGCONFIG.ROP.CALL_VALIDATION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( PWNYPOT_REGCONFIG.ROP.FORWARD_EXECUTION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( DbgGetRopFlag() == PWNYPOT_STATUS_ROP_FLAG_SET )
		{
			if ( PWNYPOT_REGCONFIG.ROP.DUMP_ROP )
			{
				DEBUG_PRINTF(LROP, NULL, "Trying to dump ROP from ESP at 0x%p and APINumber %d\n",(PVOID)lpEspAddress, RopCallee);
				DbgReportRop((PVOID)lpEspAddress,RopCallee);
			}

			if ( PWNYPOT_REGCONFIG.ROP.KILL_ROP)
				TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_VIOLATION);
		}
	}
}


/* check if WriteProcessMemory is live-patched to inject shellcode in executable memory 
 * offset for code after WriteProcessMemory: 0xbc, address windows xp: 0x7C802213 (after:7C8022CF)
 * lpAddress ist lpBaseAddress from the original WPM call, flProtect contains buffer to write
 */
extern "C"
VOID
ValidateWPM(
	IN ULONG_PTR lpEspAddress,
	IN LPVOID lpBaseAddress, 
	IN LPCVOID buffer
	)
{	
	CHAR szModuleName [MAX_MODULE_NAME32];
	PXMLNODE XmlIDLogNode;
	PXMLNODE XmlData;
	SecureZeroMemory(szModuleName, MAX_MODULE_NAME32);
	XmlIDLogNode = CreateXmlElement( XmlShellcode, "row");
    mxmlElementSetAttr(XmlIDLogNode, "type", ANALYSIS_TYPE_WPM);
    mxmlElementSetAttrf(XmlIDLogNode, "address", "%p", lpBaseAddress);
    mxmlElementSetAttrf(XmlIDLogNode, "data", "%s", buffer);
	DEBUG_PRINTF(LROP,NULL,"WriteProcessMemory call detected at baseaddress: %p \n", lpBaseAddress);
	if(DbgGetRopModule((PVOID)lpEspAddress, szModuleName, MAX_MODULE_NAME32) == PWNYPOT_STATUS_SUCCESS)
	{
    	mxmlElementSetAttrf(XmlIDLogNode, "module", "%s", szModuleName);
	}
	if(lpBaseAddress == (LPVOID)0x7C8022CF || lpBaseAddress == (LPVOID)0x7C802213) 
	{
    	mxmlElementSetAttr(XmlIDLogNode, "address_info", "Known WinXP WriteProcessMemory base Address used to avoid DEP.");
	}
	SaveXml( XmlLog );
}

STATUS
DbgSetRopFlag(
	VOID
	)
{

	/* set the ROP flag */
	bRopDetected = TRUE;

    /* init log path */
#ifndef CUCKOO
    if ( InitLogPath( PWNYPOT_REGCONFIG.LOG_PATH, MAX_PATH ) != PWNYPOT_STATUS_SUCCESS )
	{
    	ERRORINFO err;
		REPORT_ERROR("InitLogPath()", &err);
		return PWNYPOT_STATUS_GENERAL_FAIL;
	}
#endif

	return PWNYPOT_STATUS_SHELLCODE_FLAG_SET;
}

STATUS
DbgGetRopFlag(
	VOID
	)
{
	/* get current value of ROP flag */
	if ( bRopDetected )
		return PWNYPOT_STATUS_ROP_FLAG_SET;

	return PWNYPOT_STATUS_ROP_FLAG_NOT_SET;
}

STATUS
DbgGetRopModule(
	IN PVOID StackPointerAddress,
	OUT PCHAR ModuleFullName,
	IN DWORD dwSize
	)
{
	PLDR_DATA_TABLE_ENTRY TableEntry;
	DWORD ModuleCount = 0;

    /* translate StackPointerAddress to module name */
	if ( LdrFindEntryForAddress((PVOID)(*(DWORD *)StackPointerAddress), &TableEntry) == PWNYPOT_STATUS_SUCCESS )
	{
		wcstombs( ModuleFullName, TableEntry->FullDllName.Buffer, dwSize );
		return PWNYPOT_STATUS_SUCCESS;
	} 

	return PWNYPOT_STATUS_INTERNAL_ERROR;
}

VOID
DbgReportRop(
	IN CONST PVOID Address,
	IN CONST DWORD APINumber
	)
{
	PLDR_DATA_TABLE_ENTRY TableEntry;
	LPVOID lpAddress;
	LPVOID lpCodeSectionAddress;
	CHAR szAssciFullModuleName[MAX_MODULE_NAME32];
	CHAR szAssciModuleName[MAX_MODULE_NAME32];
	PCHAR szRopInst;
	CHAR szTemp[1024];
	DWORD dwCodeSectionSize;
	DWORD i;
	PXMLNODE XmlLogNode;
	PXMLNODE XmlIDLogNode;;
	PXMLNODE XmlSubNode;

	XmlIDLogNode = CreateXmlElement( XmlShellcode, "row");
    mxmlElementSetAttr(XmlIDLogNode, "type", "0");

    // data
	SecureZeroMemory(szAssciFullModuleName, MAX_MODULE_NAME32);
	SecureZeroMemory(szAssciModuleName, MAX_MODULE_NAME32);
	szRopInst = (PCHAR)LocalAlloc(LMEM_ZEROINIT, 2048);
	lpAddress = Address;
	bRopDetected = TRUE;

    /* Get function name which reports rop */
	switch (APINumber)
	{
	case CalleeVirtualAlloc:
		mxmlElementSetAttr( XmlIDLogNode, "function", "VirtualAlloc");
		break;
	case CalleeVirtualAllocEx:
		mxmlElementSetAttr( XmlIDLogNode, "function", "VirtualAllocEx");
		break;
	case CalleeVirtualProtect:
		mxmlElementSetAttr( XmlIDLogNode, "function", "VirtualProtect");
		break;
	case CalleeVirtualProtectEx:
		mxmlElementSetAttr( XmlIDLogNode, "function", "VirtualProtectEx");
		break;
	case CalleeMapViewOfFile:
		mxmlElementSetAttr( XmlIDLogNode, "function", "MapViewOfFile");
		break;
	case CalleeMapViewOfFileEx:
		mxmlElementSetAttr( XmlIDLogNode, "function", "MapViewOfFileEx");
		break;
	case CalleeWriteProcessMemory:
		mxmlElementSetAttr( XmlIDLogNode, "function", "WriteProcessMemory");
		break;
/*
	case CalleeSetProcessDEPPolicy:
		mxmlElementSetAttr( XmlIDLogNode, "function", "SetProcessDEPPolicy");
		break;
	case CalleeNtSetInformationProcess:
		mxmlElementSetAttr( XmlIDLogNode, "function", "NtSetInformationProcess");
		break;
*/
	}

    /* Get the module that used for rop gadgets */
	if ( DbgGetRopModule( lpAddress, szAssciFullModuleName, MAX_MODULE_NAME32) == PWNYPOT_STATUS_SUCCESS )
	{
		DEBUG_PRINTF(LROP, NULL, "Rop Module name: %s\n", szAssciFullModuleName);
		mxmlElementSetAttr( XmlIDLogNode, "module", szAssciFullModuleName);
	}

    /* Dump possible ROP gadgets */
	if ( PWNYPOT_REGCONFIG.ROP.DUMP_ROP == TRUE )
	{
		lpAddress = (PVOID)((DWORD_PTR)lpAddress - PWNYPOT_REGCONFIG.ROP.ROP_MEM_FAR);

		XmlLogNode = CreateXmlElement ( XmlIDLogNode, "rop_gadget");
		for ( i = 0 ; i <= PWNYPOT_REGCONFIG.ROP.MAX_ROP_MEM ; i++ , lpAddress = (LPVOID)((DWORD)lpAddress + 4) )
		{
			if ( LdrFindEntryForAddress((PVOID)(*(DWORD *)lpAddress), &TableEntry) == PWNYPOT_STATUS_SUCCESS )
			{
				/* get module name */
				wcstombs( szAssciModuleName, TableEntry->FullDllName.Buffer, TableEntry->FullDllName.Length );

				/* Get module .text section start address */
				if ( ( lpCodeSectionAddress = PeGetCodeSectionAddress( TableEntry->DllBase ) ) == NULL )
				{
					XmlSubNode = mxmlNewElement( XmlLogNode, "error");
					mxmlNewText( XmlSubNode, 0, "FAILED -- MODULE CODE SECTION ADDRESS NULL");
					DEBUG_PRINTF(LROP, NULL, "FAILED -- MODULE CODE SECTION ADDRESS NULL\n");
					break;
				}

				/* Get module .text section size */
				if ( ( dwCodeSectionSize = PeGetCodeSectionSize( TableEntry->DllBase ) ) == NULL )
				{
					XmlSubNode = mxmlNewElement( XmlLogNode, "error");
					mxmlNewText( XmlSubNode, 0, "FAILED -- MODULE CODE SECTION SIZE NULL");
					DEBUG_PRINTF(LROP, NULL, "FAILED -- MODULE CODE SECTION SIZE NULL\n");
					break;
				}

				/* Check if instruction lies inside the .text section */
				if ( (*(ULONG_PTR *)lpAddress) >= (ULONG_PTR)lpCodeSectionAddress && (*(ULONG_PTR *)lpAddress) < ( (ULONG_PTR)lpCodeSectionAddress + dwCodeSectionSize ) )
				{

					if ( ShuDisassmbleRopInstructions( (PVOID)(*(ULONG_PTR *)lpAddress), szRopInst, PWNYPOT_REGCONFIG.ROP.MAX_ROP_INST ) == PWNYPOT_STATUS_SUCCESS )
					{
						XmlLogNode = CreateXmlElement ( XmlIDLogNode, "rop_gadget");
						mxmlElementSetAttrf(XmlLogNode, "offset", "0x%p", (*(ULONG_PTR *)lpAddress - (ULONG_PTR)TableEntry->DllBase));
						DEBUG_PRINTF(LROP, NULL, "found rop_module: \n", szTemp);

						XmlSubNode = mxmlNewElement( XmlLogNode, "rop_inst");
        				memset( szTemp, '\0', 1024 );
						sprintf( szTemp, "%s", szRopInst );	
						mxmlNewText( XmlSubNode, 0, szTemp );	
						DEBUG_PRINTF(LROP, NULL, "found rop_inst: \n%s \n", szTemp);
					} 
					else
					{
						XmlSubNode = mxmlNewElement( XmlLogNode, "error");
						mxmlNewText( XmlSubNode, 0, "FAILED TO DISASSMBLE");
						DEBUG_PRINTF(LROP, NULL, "FAILED TO DISASSMBLE\n");
					}

					SecureZeroMemory(szRopInst, 2048);

				} else {
					XmlSubNode = mxmlNewElement( XmlLogNode, "error");
					mxmlNewText( XmlSubNode, 0, "OUT OF CODE SECTION");
				}
			}
			else  {
				XmlSubNode = mxmlNewElement( XmlLogNode, "stack_val");
	        	memset( szTemp, '\0', 1024 );
				sprintf( szTemp, "0x%p", lpAddress);
				mxmlElementSetAttr( XmlSubNode, "address", szTemp);
	        	memset( szTemp, '\0', 1024 );
				sprintf( szTemp, "0x%p", (*(ULONG_PTR *)lpAddress));
				mxmlElementSetAttr( XmlSubNode, "value", szTemp);

			}
		}
	}

	DEBUG_PRINTF(LDBG, NULL, "Trying to save ROP gadget XML File\n");
	SaveXml( XmlLog );
	LocalFree(szRopInst);
}
