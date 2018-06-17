#pragma once

extern "C" void statelog_impl(const char *file, const char *func, int line, const char *msg, ...);

#define statelog(msg, ...) statelog_impl(__file__, __func__, __line__, msg, __VA_ARGS__);
#define statelog_puts(msg) statelog("%s", msg)

#define statelog_var(s, f, v) statelog(s " = %" f, v)

#define statelog_iv(v, x) statelog_var(v, "i", x)
#define statelog_sv(s, x) statelog_var(s, "s", x)
#define statelog_dv(d, x) statelog_var(d, "f", x)
#define statelog_xv(v, x) statelog_var(v, "x", x)

#define statelog_i(v) statelog_iv(#v, v)
#define statelog_l(v) statelog_iv(#v, v)
#define statelog_d(v) statelog_dv(#v, v)
#define statelog_x(v) statelog_xv(#v, v)

#define statelog_alloc_ok(v) statelog_sv(#v, "allocated successfully")

#define statelog_s(v)					\
	do {								\
		if (v) {						\
			statelog_sv(#v, (v));		\
		} else {						\
			statelog_sv(#v, "NULL");	\
		}								\
	} while(0)

#define statelog_b(v) 					\
	do {								\
		if (v) {						\
			statelog_sv(#v, "true");	\
		} else {						\
			statelog_sv(#v, "false");	\
		}								\
	} while(0)