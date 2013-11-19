#pragma once
#include "mxml\src\mxml-2.7\mxml.h"
#include "LogInfo.h"
#include "ParseConfig.h"

extern PWNYPOTREGCONFIG PWNYPOT_REGCONFIG;
typedef mxml_node_t XMLNODE;
typedef mxml_node_t* PXMLNODE;

PXMLNODE
NewXmlRoot(
	IN CONST PCHAR Name
	);

PXMLNODE
CreateXmlElement(
	IN PXMLNODE ParentXmlNode,
	IN CONST PCHAR Name
	);


PXMLNODE
SetTextNode(
	IN PXMLNODE ParentXmlNode,
	IN DWORD WhiteSpace,
	IN CONST PCHAR Value
	);

STATUS
SaveXml(
	IN PXMLNODE TopElement
	);

const char	*WhiteSpaceCb(mxml_node_t *node, int where);