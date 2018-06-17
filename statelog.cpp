#include "statelog.h"
#include "miner.h"

void statelog_impl(const char *file, const char *func, int line, const char *fmt, ...)
{
	/* this is slow and dumb, but it's for debugging only and time is of the essence... */

	char buffer[4096];
	memset(buffer, 0, sizeof(buffer));

	char prefix[256];
	memset(prefix, 0, sizeof(prefix));
	strcat(prefix, "[statelog|");
	strcat(prefix, file);
	strcat(prefix, ":");
	strcat(prefix, func);
	strcat(prefix, ":");
	sprintf(&prefix[strlen(prefix)], "%i", line);
	strcat(prefix, "] ");
	
	size_t preflen = strlen(prefix);

	memcpy(&buffer[0], &prefix[0], preflen);

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(&buffer[preflen], sizeof(buffer) - 1, fmt, ap);
	va_end(ap);

	applog(LOG_BLUE, "%s", buffer);
}