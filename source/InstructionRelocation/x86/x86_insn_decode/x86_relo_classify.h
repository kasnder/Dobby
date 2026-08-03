#ifndef X86_RELO_CLASSIFY_H
#define X86_RELO_CLASSIFY_H

#include "x86_insn_decode.h"

#ifdef __cplusplus
extern "C" {
#endif

/* How a decoded instruction has to be rewritten when it is copied into a trampoline at a
   different address. Everything except X86_RELO_COPY carries a field whose meaning depends on
   where the instruction sits. */
typedef enum {
  /* Position-independent: a verbatim copy preserves the meaning. */
  X86_RELO_COPY = 0,
  X86_RELO_JCC_REL8,
  X86_RELO_JCC_REL32,
  X86_RELO_JMP_REL8,
  X86_RELO_CALL_JMP_REL32,
  X86_RELO_RIP_RELATIVE,
  /* Carries an IP-relative field with no rewrite implemented. Callers must refuse the hook
     rather than copy the instruction and hope. */
  X86_RELO_UNSUPPORTED,
} x86_relo_kind_t;

/* Decides how `insn` must be relocated. Split out from the relocation emitter so the decision can
   be tested on the host without an assembler, a code buffer, or a target process. */
x86_relo_kind_t x86_relo_classify(const x86_insn_decode_t *insn);

#ifdef __cplusplus
}
#endif

#endif
