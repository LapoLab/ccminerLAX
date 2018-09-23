#pragma once
#include <stdint.h>

#ifndef _PFX_PTR
#ifdef _WIN64
#define _PFX_PTR  "ll"
#else
#define _PFX_PTR  "l"
#endif
#endif

#ifndef PRId64
#define PRId64 "I64"
#endif

#ifndef PRIxPTR
#define PRIxPTR _PFX_PTR "x"
#endif
