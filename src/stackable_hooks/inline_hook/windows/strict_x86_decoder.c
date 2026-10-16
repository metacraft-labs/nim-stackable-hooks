/* Proposed strict live-scan decoder; legacy ct_ild_decode remains unchanged. */
#include "strict_x86_decoder.h"
#include <Zydis/Decoder.h>
#include <Zycore/Status.h>

int ct_strict_x86_decode(const void *code, size_t available, int mode64) {
    ZydisDecoder decoder;
    ZydisDecodedInstruction instruction;
    if (!code || !available) return 0;
    const size_t bounded = available < 15u ? available : 15u;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder,
            mode64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
            mode64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32))) return 0;
    /* Full instruction validation, no MINIMAL or AMD_BRANCHES mode. */
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&decoder, NULL,
            code, bounded, &instruction))) return 0;
    if (!instruction.length || instruction.length > bounded) return 0;
    return instruction.length;
}

int ct_strict_x8664_decode(const void *code, size_t available) { return ct_strict_x86_decode(code, available, 1); }
