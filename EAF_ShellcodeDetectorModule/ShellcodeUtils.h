#pragma once
#include <Winsock2.h>
#include <stdio.h>
#include <tlhelp32.h> 
#include <time.h>
#include <UrlMon.h>
#include "LogInfo.h"
#include "ParseConfig.h"
#include "distorm\include\distorm.h"
#pragma comment(lib,"distorm\\distorm.lib")

#define MAX_INSTRUCTIONS (10000)
#define SHELLCODE_SIZE_LIMIT 1024

extern PWNYPOTREGCONFIG PWNYPOT_REGCONFIG;

STATUS
ShuDumpShellcode(
	IN LPVOID lpAddress
	);

STATUS
ShuDisassembleShellcode(
	IN PVOID DumpedShellcode,
	IN PVOID ShellcodeAddress,
	IN DWORD dwSize
	);

STATUS
ShuDisassmbleRopInstructions(
	IN PVOID Address,
	OUT LPSTR szInstruction,
	IN DWORD Size
	);