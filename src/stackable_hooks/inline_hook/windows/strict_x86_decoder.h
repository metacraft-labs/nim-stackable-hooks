#ifndef CT_STRICT_X86_DECODER_H
#define CT_STRICT_X86_DECODER_H
#include <stddef.h>
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
#define CT_STRICT_DECODER_INTERNAL __attribute__((visibility("hidden")))
#else
/* Static internal object linkage on Windows: no dllexport decoration. */
#define CT_STRICT_DECODER_INTERNAL
#endif
CT_STRICT_DECODER_INTERNAL int ct_strict_x86_decode(const void *code, size_t available, int mode64);
CT_STRICT_DECODER_INTERNAL int ct_strict_x8664_decode(const void *code, size_t available);
#endif
