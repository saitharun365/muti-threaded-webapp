// author : Sai tharun
//
#include "pch.h"
char* extract_and_truncate(char* link, char c);

int html_parser(char* html_code, char* link, int html_content_length, HTMLParserBase*&parser, int& tamu_links)
{
	// create new parser object
	int nLinks;

	char *linkBuffer = parser->Parse (html_code, html_content_length, link, (int)strlen(link), &nLinks);

	// check for errors indicated by negative values
	if (nLinks < 0)
		nLinks = 0;

	/* Code for extracting TAMU links
	for (int i = 0; i < nLinks; i++)
	{
		char* host = NULL;
		char* org_host = host;
		int length = strlen(linkBuffer) + 1;
		host = new char[length];
		strcpy_s(host, length, linkBuffer);

		if (strncmp(host, "http://", 7) == 0)
		{
			host += 7;
		}
		else if (strncmp(host, "https://", 8) == 0) host += 8;
	
		extract_and_truncate(host, '#');
		extract_and_truncate(host, '?');
		extract_and_truncate(host, '/');
		extract_and_truncate(host, ':');

		//tamu.edu
		if (strlen(host) >= 8 && strcmp(host + strlen(host) - 8, "tamu.edu") == 0) tamu_links++;

		delete[] org_host;

		linkBuffer += strlen(linkBuffer) + 1;
	}
	*/

	return nLinks;
}

