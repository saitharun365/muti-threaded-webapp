#include "pch.h"

char* extract_and_truncate(char* link, char c)
{
	char* result = NULL;
	char* temp = strchr(link, c);
	if (temp != NULL) {
		int length = strlen(temp) + 1;
		result = new char[length];
		strcpy_s(result, length, temp);
		*temp = '\0';
	}
	return result;
}