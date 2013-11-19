#pragma once
#include <Winsock2.h>
#include "LogInfo.h"


STATUS
InjectDLLIntoProcess(
	IN PCHAR szDllPath,
	IN HANDLE hProcessHandle
	);