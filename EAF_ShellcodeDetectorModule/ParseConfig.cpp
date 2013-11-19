#include "ParseConfig.h"	

#ifndef CUCKOO
STATUS
ParseRegConfig(
	OUT PPWNYPOTREGCONFIG pPwnyPotRegConfig,
	IN PCHAR szAppPathHash,
	IN DWORD Size
	)
{
	HKEY hKey;
	VALENT AppRegConfig[32];
	VALENT MainRegConfig[2];
	CHAR szConfigKey[MAX_PATH];
	PCHAR ConfigBuffer;
	DWORD dwBufferSize;
	DWORD i;
	PDWORD pdwFlag;
	ERRORINFO err;
	DWORD dwStatus;

	AppRegConfig[0].ve_valuename = "MalwareExecution";
	AppRegConfig[1].ve_valuename = "MalwareDownload";
	AppRegConfig[2].ve_valuename = "KillShellcode";
	AppRegConfig[3].ve_valuename = "AnalysisShellcode";
	AppRegConfig[4].ve_valuename = "SkipHWBError";
	AppRegConfig[5].ve_valuename = "EtaValidation";
	AppRegConfig[6].ve_valuename = "KillRop";
	AppRegConfig[7].ve_valuename = "DumpRop";
	AppRegConfig[8].ve_valuename = "MaxRopInst";
	AppRegConfig[9].ve_valuename = "MaxRopMemory";
	AppRegConfig[10].ve_valuename = "InitDelay";
	AppRegConfig[11].ve_valuename = "AvoidHeapSpray";
	AppRegConfig[12].ve_valuename = "NullPageAllocation";
	AppRegConfig[13].ve_valuename = "SEHOverwriteProtection";
	AppRegConfig[14].ve_valuename = "PivotDetection";
	AppRegConfig[15].ve_valuename = "PivotThreshold";
	AppRegConfig[16].ve_valuename = "SyscallValidation";
	AppRegConfig[17].ve_valuename = "CallValidation";
	AppRegConfig[18].ve_valuename = "ForwardExecution";
	AppRegConfig[19].ve_valuename = "AppID";
	AppRegConfig[20].ve_valuename = "TextSecrionOverwrite";
	AppRegConfig[21].ve_valuename = "StackExecution";
	AppRegConfig[22].ve_valuename = "StackMonitoring";
	AppRegConfig[23].ve_valuename = "TextSectionRandomization";
	AppRegConfig[24].ve_valuename = "AppFullPath";
	AppRegConfig[25].ve_valuename = "EtaModules";
	AppRegConfig[26].ve_valuename = "RopDetection";
	AppRegConfig[27].ve_valuename = "DumpShellcode";
	AppRegConfig[28].ve_valuename = "MemFar";
	AppRegConfig[29].ve_valuename = "FeDept";
	AppRegConfig[30].ve_valuename = "PermanentDEP";
	AppRegConfig[31].ve_valuename = "PivotInstThreshold";
	AppRegConfig[32].ve_valuename = "HeapSprayAddress";

	dwBufferSize = 0;


	if ( szAppPathHash != NULL )
	{
		strncpy(szConfigKey, APP_CONFIG_KEY, Size);
		strncat(szConfigKey, szAppPathHash, Size );

		dwStatus = RegOpenKeyEx( HKEY_CURRENT_USER,
		                         szConfigKey,
		                         0,
		                         KEY_QUERY_VALUE,
		                         &hKey);

		if ( dwStatus != ERROR_SUCCESS )
		{
			DEBUG_PRINTF(LDBG, NULL, "Can't load Config (ERROR_SUCCESS)!\n");
			REPORT_ERROR("RegOpenKeyEx()", &err);
			return PWNYPOT_STATUS_INTERNAL_ERROR;
		}

		dwStatus = RegQueryMultipleValues( hKey, 
			                               AppRegConfig, 
										   sizeof(AppRegConfig)/sizeof(VALENT), 
										   NULL, 
										   &dwBufferSize);
		if ( dwStatus != ERROR_MORE_DATA )
		{
			DEBUG_PRINTF(LDBG, NULL, "Can't load Config (AppRegConfig 1)!\n");
			REPORT_ERROR("RegQueryMultipleValues()", &err);
			return PWNYPOT_STATUS_INTERNAL_ERROR;
		}

		ConfigBuffer = (PCHAR)LocalAlloc( LMEM_ZEROINIT, dwBufferSize );

		if ( ConfigBuffer == NULL )
		{
			DEBUG_PRINTF(LDBG, NULL, "Can't load Config (ConfigBuffer)!\n");
			REPORT_ERROR("LocalAlloc()", &err);
			return PWNYPOT_STATUS_INTERNAL_ERROR;
		}

		dwStatus = RegQueryMultipleValues( hKey, 
			                               AppRegConfig, 
										   sizeof(AppRegConfig)/sizeof(VALENT), 
										   ConfigBuffer, 
										   &dwBufferSize);
		if ( dwStatus != ERROR_SUCCESS )
		{
			DEBUG_PRINTF(LDBG, NULL, "Can't load Config (AppRegConfig ConfigBuffer)!\n");
			REPORT_ERROR("RegQueryMultipleValues()", &err);
			return PWNYPOT_STATUS_INTERNAL_ERROR;
		}

		for( i = 0; i < sizeof(AppRegConfig)/sizeof(VALENT); i++) 
		{
			if ( AppRegConfig[i].ve_type == REG_DWORD )
			{
				pdwFlag = (PDWORD)AppRegConfig[i].ve_valueptr;
			}

			if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "SkipHWBError") ) 
			{
				pPwnyPotRegConfig->SKIP_HBP_ERROR = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "InitDelay") ) 
			{
				pPwnyPotRegConfig->INIT_DELAY = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "AppID") ) 
			{
				pPwnyPotRegConfig->APP_ID = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "AppFullPath") ) 
			{
				strncpy( pPwnyPotRegConfig->APP_PATH, (const char*)AppRegConfig[i].ve_valueptr, MAX_PATH );
			}					
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "EtaModules") ) 
			{
				strncpy( pPwnyPotRegConfig->SHELLCODE.ETA_MODULE, (const char*)AppRegConfig[i].ve_valueptr, MAX_MODULE_NAME32 );
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "MalwareExecution") ) 
			{
				pPwnyPotRegConfig->GENERAL.ALLOW_MALWARE_EXEC = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "MalwareDownload") ) 
			{
				pPwnyPotRegConfig->SHELLCODE.ALLOW_MALWARE_DOWNLOAD = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "KillShellcode") ) 
			{
				pPwnyPotRegConfig->SHELLCODE.KILL_SHELLCODE = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "EtaValidation") ) 
			{
				pPwnyPotRegConfig->SHELLCODE.ETA_VALIDATION = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "SyscallValidation") ) 
			{
				pPwnyPotRegConfig->SHELLCODE.SYSCALL_VALIDATION = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "AnalysisShellcode") ) 
			{
				pPwnyPotRegConfig->SHELLCODE.ANALYSIS_SHELLCODE = *pdwFlag;
			}	
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "DumpShellcode") ) 
			{
				pPwnyPotRegConfig->SHELLCODE.DUMP_SHELLCODE = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "KillRop") ) 
			{
				pPwnyPotRegConfig->ROP.KILL_ROP = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "PivotDetection") ) 
			{
				pPwnyPotRegConfig->ROP.PIVOT_DETECTION = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "PivotThreshold") ) 
			{
				pPwnyPotRegConfig->ROP.PIVOT_TRESHOLD = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "PivotInstThreshold") ) 
			{
				pPwnyPotRegConfig->ROP.PIVOT_INST_TRESHOLD = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "DumpRop") ) 
			{
				pPwnyPotRegConfig->ROP.DUMP_ROP = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "MaxRopInst") ) 
			{
				pPwnyPotRegConfig->ROP.MAX_ROP_INST = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "MaxRopMemory") ) 
			{
				pPwnyPotRegConfig->ROP.MAX_ROP_MEM = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "CallValidation") ) 
			{
				pPwnyPotRegConfig->ROP.CALL_VALIDATION = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "ForwardExecution") ) 
			{
				pPwnyPotRegConfig->ROP.FORWARD_EXECUTION = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "FeDept") ) 
			{
				pPwnyPotRegConfig->ROP.FE_FAR = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "StackMonitoring") ) 
			{
				pPwnyPotRegConfig->ROP.STACK_MONITOR = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "RopDetection") ) 
			{
				pPwnyPotRegConfig->ROP.DETECT_ROP = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "MemFar") ) 
			{
				pPwnyPotRegConfig->ROP.ROP_MEM_FAR = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "TextSecrionOverwrite") ) 
			{
				pPwnyPotRegConfig->MEM.TEXT_RWX = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "StackExecution") ) 
			{
				pPwnyPotRegConfig->MEM.STACK_RWX = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "TextSectionRandomization") ) 
			{
				pPwnyPotRegConfig->MEM.TEXT_RANDOMIZATION = *pdwFlag;
			}			
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "AvoidHeapSpray") ) 
			{
				pPwnyPotRegConfig->GENERAL.HEAP_SPRAY = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "HeapSprayAddress") ) 
			{
				/* I hope this never fail */
				pPwnyPotRegConfig->GENERAL.HEAP_SPRAY_ADDRESSES = (PCHAR)LocalAlloc(LMEM_ZEROINIT, strlen((const char*)AppRegConfig[i].ve_valueptr)+MAX_PATH);
				strcpy( pPwnyPotRegConfig->GENERAL.HEAP_SPRAY_ADDRESSES, (const char*)AppRegConfig[i].ve_valueptr);
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "NullPageAllocation") ) 
			{
				pPwnyPotRegConfig->GENERAL.NULL_PAGE = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "SEHOverwriteProtection") ) 
			{
				pPwnyPotRegConfig->GENERAL.SEHOP = *pdwFlag;
			}
			else if ( MATCH_CONF(AppRegConfig[i].ve_valuename, "PermanentDEP") ) 
			{
				pPwnyPotRegConfig->GENERAL.PERMANENT_DEP = *pdwFlag;
			}
		}

		strncpy( pPwnyPotRegConfig->APP_PATH_HASH, szAppPathHash, MAX_MODULE_NAME32 );
		RegCloseKey(hKey);
		LocalFree( ConfigBuffer );
	}

	MainRegConfig[0].ve_valuename = "LogPath";
	MainRegConfig[1].ve_valuename = "McedpModulePath";
	dwBufferSize = 0;

	dwStatus = RegOpenKeyEx( HKEY_CURRENT_USER,
		                     MAIN_CONFIG_KEY,
		                     0,
		                     KEY_QUERY_VALUE,
		                     &hKey);

	if ( dwStatus != ERROR_SUCCESS )
	{
		DEBUG_PRINTF(LDBG, NULL, "Can't load Config (MAIN_CONFIG_KEY)!\n");
		REPORT_ERROR("RegOpenKeyEx()", &err);
		return PWNYPOT_STATUS_INTERNAL_ERROR;
	}

	dwStatus = RegQueryMultipleValues(	hKey, 
										MainRegConfig, 
										sizeof(MainRegConfig)/sizeof(VALENT), 
										NULL, 
										&dwBufferSize);
	if ( dwStatus != ERROR_MORE_DATA )
	{
		DEBUG_PRINTF(LDBG, NULL, "Can't load Config (MainRegConfig)!\n");
		REPORT_ERROR("RegQueryMultipleValues()", &err);
		return PWNYPOT_STATUS_INTERNAL_ERROR;
	}

	ConfigBuffer = (PCHAR)LocalAlloc( LMEM_ZEROINIT, dwBufferSize );

	if ( ConfigBuffer == NULL )
	{
		DEBUG_PRINTF(LDBG, NULL, "Can't load Config (ConfigBuffer)!\n");
		REPORT_ERROR("LocalAlloc()", &err);
		return PWNYPOT_STATUS_INTERNAL_ERROR;
	}
	dwStatus = RegQueryMultipleValues(	hKey, 
										MainRegConfig, 
										sizeof(MainRegConfig)/sizeof(VALENT), 
										ConfigBuffer, 
										&dwBufferSize);
	if ( dwStatus != ERROR_SUCCESS )
	{
		DEBUG_PRINTF(LDBG, NULL, "Can't load Config (MainRegConfig ConfigBuffer)!\n");
		REPORT_ERROR("RegQueryMultipleValues()", &err);
		return PWNYPOT_STATUS_INTERNAL_ERROR;
	}
	for( i = 0; i < sizeof(MainRegConfig)/sizeof(VALENT); i++) 
	{
		if (  MATCH_CONF(MainRegConfig[i].ve_valuename, "LogPath") )
		{			
			strncpy( pPwnyPotRegConfig->LOG_PATH, (const char*)MainRegConfig[i].ve_valueptr, MAX_PATH );
            strncpy( pPwnyPotRegConfig->DBG_LOG_PATH, pPwnyPotRegConfig->LOG_PATH, MAX_PATH );
            strncat( pPwnyPotRegConfig->DBG_LOG_PATH, "\\", MAX_PATH );
            strncat( pPwnyPotRegConfig->DBG_LOG_PATH, szAppPathHash, MAX_PATH );
		}
		else if ( MATCH_CONF(MainRegConfig[i].ve_valuename, "McedpModulePath") )
		{
			strncpy( pPwnyPotRegConfig->PWNYPOT_MODULE_PATH, (const char*)MainRegConfig[i].ve_valueptr, MAX_PATH );
		}
	}
	
	pPwnyPotRegConfig->PROCESS_HOOKED = FALSE;

	RegCloseKey(hKey);
	LocalFree( ConfigBuffer );
	return PWNYPOT_STATUS_SUCCESS;
}

#else 
STATUS
ParseConfig(
	OUT PPWNYPOTREGCONFIG pPwnyPotRegConfig
	)
{	
	LOCAL_DEBUG_PRINTF("Using Cookoo Paths.\n");
	char buf[512], config_fname[MAX_PATH];

	// Read Randomized Directory names and resultserver info from ini file
    sprintf(config_fname, "%s\\%d.ini",getenv("TEMP"), GetCurrentProcessId(), MAX_PATH);
	LOCAL_DEBUG_PRINTF("Trying to load Cuckoo Config from %s.\n",config_fname);
	FILE *fp = fopen(config_fname, "r");
	if(fp != NULL) {
	    while (fgets(buf, sizeof(buf), fp) != NULL) {
		    // cut off the newline
		    char *p = strchr(buf, '\r');
	    	if(p != NULL) *p = 0;
		    p = strchr(buf, '\n');
		    if(p != NULL) *p = 0;
        	// split key=value
        	p = strchr(buf, '=');
	        if(p != NULL) {
    	        *p = 0;
        	    const char *key = buf, *value = p + 1;
            	if(!strcmp(key, "results")) {		 
            		// setting paths for logs
	                strncpy(pPwnyPotRegConfig->LOG_PATH, value, MAX_PATH);
					LOCAL_DEBUG_PRINTF("Found Results Path %s.\n",value);
	                strncat(pPwnyPotRegConfig->LOG_PATH, "\\logs",MAX_PATH);
					LOCAL_DEBUG_PRINTF("Setting Logs Path %s.\n",pPwnyPotRegConfig->LOG_PATH);
    	            strncpy(pPwnyPotRegConfig->DBG_LOG_PATH, pPwnyPotRegConfig->LOG_PATH,MAX_PATH);
        	    }
        	    if(!strcmp(key, "pipe")) {
                     strncpy(pPwnyPotRegConfig->CUCKOO_PIPE_NAME, value,MAX_PATH);
                }
        	    if(!strcmp(key, "analyzer")) {
                     strncpy(pPwnyPotRegConfig->CUCKOO_ANALYZER_DIR, value,MAX_PATH);
                }
                else if(!strcmp(key, "host-ip")) {        
    				strncpy(pPwnyPotRegConfig->RESULT_SERVER_IP, value, MAX_PATH);
                }
                else if(!strcmp(key, "host-port")) {        
    				pPwnyPotRegConfig->RESULT_SERVER_PORT = atoi(value);
                }
                else if(!strcmp(key, "dll-path")) {        
                    strncpy(pPwnyPotRegConfig->DLL_PATH, value, MAX_PATH);
                }
        	}
	    }
    	fclose(fp);
	    DeleteFile(config_fname);
    }    
    else {
        LOCAL_DEBUG_PRINTF("Loading Cuckoo Configuration failed: ini File not found.\n");
		return PWNYPOT_STATUS_INTERNAL_ERROR;
    }  

    // Read PwnyPot configuration variables from analysis.conf
    memset(config_fname, '\0', MAX_PATH); 
    sprintf(config_fname, "%s\\analysis.conf",pPwnyPotRegConfig->CUCKOO_ANALYZER_DIR, MAX_PATH);
	LOCAL_DEBUG_PRINTF("Trying to load PwnyPot Config from %s.\n",config_fname);
	fp = fopen(config_fname, "r");
	if(fp != NULL) {
	    while (fgets(buf, sizeof(buf), fp) != NULL) {
		    // cut off the newline
		    char *p = strchr(buf, '\r');
	    	if(p != NULL) *p = 0;
		    p = strchr(buf, '\n');
		    if(p != NULL) *p = 0;
        	// split key=value
        	p = strchr(buf, ' =');
	        if(p != NULL) {
    	        *p = 0;
        	    const char *key = buf, *value = p + 2;
        	    if(!strcmp(key, "skip_hbp_error ")) {
                    pPwnyPotRegConfig->SKIP_HBP_ERROR = atoi(value);
                }
        	    else if(!strcmp(key, "init_delay ")) {
                    pPwnyPotRegConfig->INIT_DELAY = atoi(value);
                }

                /* GENERAL */
        	    else if(!strcmp(key, "permanent_dep ")) {
                    pPwnyPotRegConfig->GENERAL.PERMANENT_DEP = atoi(value);
                }
                else if(!strcmp(key, "sehop ")) {
                    pPwnyPotRegConfig->GENERAL.SEHOP = atoi(value);
                }
                else if(!strcmp(key, "sehop_simple ")) {
                    pPwnyPotRegConfig->GENERAL.SEHOP_SIMPLE = atoi(value);
                }
                else if(!strcmp(key, "force_pwnypot_sehop ")) {
                    pPwnyPotRegConfig->GENERAL.FORCE_SEHOP = atoi(value);
                }
        	    else if(!strcmp(key, "null_page ")) {
                    pPwnyPotRegConfig->GENERAL.NULL_PAGE = atoi(value);
                }
        	    else if(!strcmp(key, "heap_spray ")) {
                    pPwnyPotRegConfig->GENERAL.HEAP_SPRAY = atoi(value);
                }                
                else if(!strcmp(key, "heap_spray_addresses ")) {
                    /* I hope this never fail */
                    pPwnyPotRegConfig->GENERAL.HEAP_SPRAY_ADDRESSES = (PCHAR)LocalAlloc(LMEM_ZEROINIT, strlen(value)+MAX_PATH);
                    strcpy( pPwnyPotRegConfig->GENERAL.HEAP_SPRAY_ADDRESSES, value);
                }
        	    else if(!strcmp(key, "allow_malware_exec ")) {
                    pPwnyPotRegConfig->GENERAL.ALLOW_MALWARE_EXEC = atoi(value);
                }

                /* SHELLCODE */
        	    else if(!strcmp(key, "analysis_shellcode ")) {
                    pPwnyPotRegConfig->SHELLCODE.ANALYSIS_SHELLCODE = atoi(value);
                }
        	    else if(!strcmp(key, "syscall_validation ")) {
                    pPwnyPotRegConfig->SHELLCODE.SYSCALL_VALIDATION = atoi(value);
                }
        	    else if(!strcmp(key, "eta_validation ")) {
                    pPwnyPotRegConfig->SHELLCODE.ETA_VALIDATION = atoi(value);
                }
        	    else if(!strcmp(key, "eta_module ")) {
					strncpy( pPwnyPotRegConfig->SHELLCODE.ETA_MODULE, value, MAX_MODULE_NAME32 );	
                }
        	    else if(!strcmp(key, "kill_shellcode ")) {
                    pPwnyPotRegConfig->SHELLCODE.KILL_SHELLCODE = atoi(value);
                }
        	    else if(!strcmp(key, "dump_shellcode ")) {
                    pPwnyPotRegConfig->SHELLCODE.DUMP_SHELLCODE = atoi(value);
                }
        	    else if(!strcmp(key, "allow_malware_download ")) {
                    pPwnyPotRegConfig->SHELLCODE.ALLOW_MALWARE_DOWNLOAD = atoi(value);
                }

                /* ROP */
        	    else if(!strcmp(key, "detect_rop ")) {
                    pPwnyPotRegConfig->ROP.DETECT_ROP = atoi(value);
                }
        	    else if(!strcmp(key, "dump_rop ")) {
                    pPwnyPotRegConfig->ROP.DUMP_ROP = atoi(value);
                }
        	    else if(!strcmp(key, "rop_mem_far ")) {
                    pPwnyPotRegConfig->ROP.ROP_MEM_FAR = atoi(value);					
                }
        	    else if(!strcmp(key, "forward_execution ")) {
                    pPwnyPotRegConfig->ROP.FORWARD_EXECUTION = atoi(value);
                }
        	    else if(!strcmp(key, "fe_far ")) {
                    pPwnyPotRegConfig->ROP.FE_FAR = atoi(value);					
                }
        	    else if(!strcmp(key, "kill_rop ")) {
                    pPwnyPotRegConfig->ROP.KILL_ROP = atoi(value);
                }
        	    else if(!strcmp(key, "call_validation ")) {
                    pPwnyPotRegConfig->ROP.CALL_VALIDATION = atoi(value);
                }
        	    else if(!strcmp(key, "stack_monitor ")) {
                    pPwnyPotRegConfig->ROP.STACK_MONITOR = atoi(value);
                }
        	    else if(!strcmp(key, "max_rop_inst ")) {
                    pPwnyPotRegConfig->ROP.MAX_ROP_INST = atoi(value);
                }
        	    else if(!strcmp(key, "max_rop_mem ")) {
                    pPwnyPotRegConfig->ROP.MAX_ROP_MEM = atoi(value);
                }
        	    else if(!strcmp(key, "pivot_detection ")) {
                    pPwnyPotRegConfig->ROP.PIVOT_DETECTION = atoi(value);
                }
        	    else if(!strcmp(key, "pivot_threshold ")) {
                    pPwnyPotRegConfig->ROP.PIVOT_TRESHOLD = atoi(value);
                }
        	    else if(!strcmp(key, "pivot_inst_threshold ")) {
                    pPwnyPotRegConfig->ROP.PIVOT_INST_TRESHOLD = atoi(value);
                }

                /* MEMORY */
        	    else if(!strcmp(key, "text_rwx ")) {
                    pPwnyPotRegConfig->MEM.TEXT_RWX = atoi(value);
                }
        	    else if(!strcmp(key, "stack_rwx ")) {
                    pPwnyPotRegConfig->MEM.STACK_RWX = atoi(value);
                }
        	    else if(!strcmp(key, "text_randomization ")) {
                    pPwnyPotRegConfig->MEM.TEXT_RANDOMIZATION = atoi(value);
                }
        	}
	    }
    	fclose(fp);
    }    
    else {
        LOCAL_DEBUG_PRINTF("Loading Cuckoo Configuration failed: analysis.conf File not found.\n");
		return PWNYPOT_STATUS_INTERNAL_ERROR;
    }  

	pPwnyPotRegConfig->PROCESS_HOOKED = FALSE;
	return PWNYPOT_STATUS_SUCCESS;
}
#endif 