#include "platform_detect_macro.h"
#if defined(TARGET_ARCH_IA32) || defined(TARGET_ARCH_X64)

#include "x86_relo_classify.h"

x86_relo_kind_t x86_relo_classify(const x86_insn_decode_t *insn) {
  /* If the decoder could not model the encoding its length is a guess, and relocating on a
     guessed length desynchronises everything after it. Refuse before looking at anything else. */
  if (insn->flags & X86_INSN_DECODE_FLAG_UNDECODABLE) {
    return X86_RELO_UNSUPPORTED;
  }

  const int two_byte = (insn->flags & X86_INSN_DECODE_FLAG_TWO_BYTE_OPCODE) != 0;

  /* A RIP-relative memory operand is independent of the opcode's length, so it is settled first.
     The decoder always parks the memory operand in operands[1], whichever side of the
     instruction it is written on. */
  if ((insn->flags & X86_INSN_DECODE_FLAG_IP_RELATIVE) && insn->operands[1].mem.base == RIP) {
    return X86_RELO_RIP_RELATIVE;
  }

  if (two_byte) {
    /* 0F 80..8F: jcc rel32. The near form of every conditional branch -- what a compiler emits
       whenever the target is further away than a signed byte reaches. */
    if (insn->primary_opcode >= 0x80 && insn->primary_opcode <= 0x8F) {
      return X86_RELO_JCC_REL32;
    }
    /* Every other two-byte opcode is position-independent unless it took the RIP path above. */
    return X86_RELO_COPY;
  }

  if (insn->primary_opcode >= 0x70 && insn->primary_opcode <= 0x7F) {
    return X86_RELO_JCC_REL8;
  }
  if (insn->primary_opcode == 0xEB) {
    return X86_RELO_JMP_REL8;
  }
  if (insn->primary_opcode == 0xE8 || insn->primary_opcode == 0xE9) {
    return X86_RELO_CALL_JMP_REL32;
  }
  /* E0..E3 are LOOPNZ/LOOPZ/LOOP/JrCXZ. They carry a rel8 field and have no rewrite here, so they
     fail closed instead of being copied with a stale displacement. */
  if (insn->primary_opcode >= 0xE0 && insn->primary_opcode <= 0xE3) {
    return X86_RELO_UNSUPPORTED;
  }

  return X86_RELO_COPY;
}

#endif
