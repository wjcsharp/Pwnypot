#include "XmlLog.h"

PXMLNODE
NewXmlRoot(
	IN CONST PCHAR Name
	)
{
	return ( mxmlNewXML(Name) );
}

PXMLNODE
CreateXmlElement(
	IN PXMLNODE ParentXmlNode,
	IN CONST PCHAR Name
	)
{
	return (mxmlNewElement( ParentXmlNode, Name ) );
}

PXMLNODE
SetTextNode(
	IN PXMLNODE ParentXmlNode,
	IN DWORD WhiteSpace,
	IN CONST PCHAR Value
	)
{
	return ( mxmlNewText( ParentXmlNode, WhiteSpace, Value) );
}

/*
 * Copyright 2003-2011 by Michael R Sweet.
 *
 * These coded instructions, statements, and computer programs are the
 * property of Michael R Sweet and are protected by Federal copyright
 * law.  Distribution and use rights are outlined in the file "COPYING"
 * which should have been included with this file.  If this file is
 * missing or damaged, see the license at:
 *
 *     http://www.minixml.org/
 *
 * Contents:

 *   whitespace_cb() - Let the mxmlSaveFile() function know when to insert
 *                     newlines and tabs...
 */
const char *				/* O - Whitespace string or NULL */
WhiteSpaceCb(
	mxml_node_t *node,	/* I - Element node */
    int         where	/* I - Open or close tag? */
    )	
{
	mxml_node_t	*parent;		/* Parent node */
  	int		level;			/* Indentation level */
  	const char	*name;			/* Name of element */
  	static const char *tabs = "\t\t\t\t\t\t\t\t";
					/* Tabs for indentation */


	/*
	 * We can conditionally break to a new line before or after any element.
	 * These are just common HTML elements...
	 */

  	name = node->value.element.name;

  	if (!strcmp(name, "html") || !strcmp(name, "head") || !strcmp(name, "body") ||
      	!strcmp(name, "pre") || !strcmp(name, "p") ||
      	!strcmp(name, "h1") || !strcmp(name, "h2") || !strcmp(name, "h3") ||
      	!strcmp(name, "h4") || !strcmp(name, "h5") || !strcmp(name, "h6"))
  	{
    /*
     * Newlines before open and after close...
     */

    	if (where == MXML_WS_BEFORE_OPEN || where == MXML_WS_AFTER_CLOSE)
      		return ("\n");
  	}
  	else if (!strcmp(name, "dl") || !strcmp(name, "ol") || !strcmp(name, "ul"))
  	{
	   /*
	    * Put a newline before and after list elements...
	    */
    	return ("\n");
  	}
  	else if (!strcmp(name, "dd") || !strcmp(name, "dt") || !strcmp(name, "li"))
  	{
	   /*
	    * Put a tab before <li>'s, <dd>'s, and <dt>'s, and a newline after them...
	    */

    	if (where == MXML_WS_BEFORE_OPEN)
      		return ("\t");
    	else if (where == MXML_WS_AFTER_CLOSE)
      		return ("\n");
  	}
  	else if (!strncmp(name, "?xml", 4))
  	{
    	if (where == MXML_WS_AFTER_OPEN)
     		return ("\n");
    	else
      		return (NULL);
  	}
  	else if (where == MXML_WS_BEFORE_OPEN || ((!strcmp(name, "choice") || !strcmp(name, "option")) &&
	    where == MXML_WS_BEFORE_CLOSE))
  	{
    	for (level = -1, parent = node->parent;
        	parent;
	 		level ++, parent = parent->parent);

    	if (level > 8)
      		level = 8;
    	else if (level < 0)
      		level = 0;

    	return (tabs + 8 - level);
  	}
  	else if (where == MXML_WS_AFTER_CLOSE || ((!strcmp(name, "group") || !strcmp(name, "option") ||!strcmp(name, "choice")) && where == MXML_WS_AFTER_OPEN))
    	return ("\n");
  	else if (where == MXML_WS_AFTER_OPEN && !node->child)
    	return ("\n");

	/*
	 * Return NULL for no added whitespace...
	 */

	return (NULL);
}



STATUS
SaveXml(
	IN PXMLNODE TopElement
	)
{
#ifndef CUCKOO
	FILE *fp;
	ERRORINFO err;
	CHAR szLogDir[MAX_PATH];
	CHAR szFileName[MAX_PATH];

	strncpy(szLogDir, PWNYPOT_REGCONFIG.LOG_PATH, MAX_PATH);
	strncat(szLogDir, "\\", MAX_PATH);
	sprintf(szFileName, "%u_ShellcodeAnalysis", GetCurrentProcessId(),MAX_PATH);
	strncat(szLogDir, szFileName , MAX_PATH);


    fp = fopen(szLogDir, "w");

	if ( fp == NULL )
	{
		REPORT_ERROR("fopen()", &err);
		return PWNYPOT_STATUS_INTERNAL_ERROR;
	}
    if ( mxmlSaveFile(TopElement, fp, MXML_NO_CALLBACK) == -1 )
	{
		REPORT_ERROR("mxmlSaveFile()", &err);
		return PWNYPOT_STATUS_INTERNAL_ERROR;
	}
	fflush(fp);
    fclose(fp);
#else     
  const int bufLenght = 16384;
  CHAR szBuf[bufLenght];
	CHAR szFileName[MAX_PATH];
  if( mxmlSaveString(TopElement, szBuf, bufLenght, WhiteSpaceCb) <= 0) 
  {
  	LOCAL_DEBUG_PRINTF ( "Error on printing XML into buffer\n" );
  	return PWNYPOT_STATUS_INTERNAL_ERROR;
  }

	sprintf(szFileName, "logs/%u_ShellcodeAnalysis", GetCurrentProcessId(), MAX_PATH);
  if ( TransmitBufAsFile(szBuf, szFileName) != PWNYPOT_STATUS_SUCCESS ) 
  {
  	LOCAL_DEBUG_PRINTF ( "Error on transmission of file ShellcodeAnalysis\n" );
  	return PWNYPOT_STATUS_INTERNAL_ERROR;
  }
  else 
   	LOCAL_DEBUG_PRINTF ( "Successfully transmitted ShellcodeAnalysis\n" );

#endif 

	return PWNYPOT_STATUS_SUCCESS;
}

