#include "platform_detect_macro.h"

#if defined(TARGET_ARCH_IA32) || defined(TARGET_ARCH_X64)

#include "dobby/dobby_internal.h"

#include "InstructionRelocation/x86/InstructionRelocationX86.h"
#include "InstructionRelocation/x86/x86_insn_decode/x86_insn_decode.h"
#include "InstructionRelocation/x86/x86_insn_decode/x86_relo_classify.h"
#include "MemoryAllocator/NearMemoryAllocator.h"

using namespace zz::x86;

// x64 jmp absolute address
inline void codegen_x64_jmp_absolute_addr(CodeMemBuffer *buffer, addr_t target) {
  // jmp *(rip)
  buffer->Emit<int8_t>(0xFF);
  buffer->Emit<int8_t>(0x25); // ModR/M: 00 100 101
  buffer->Emit<int32_t>(0x00);
  // .long target
  buffer->Emit<int64_t>(target);
}

// simple impl for ReloLabel
inline void emit_rel32_label(CodeMemBuffer *buffer, uint32_t last_offset, addr_t curr_relo_ip, addr_t orig_dst_ip) {
  addr_t curr_offset = buffer->buffer_size;
  uint32_t relo_insn_len = curr_offset + sizeof(uint32_t) - last_offset;
  addr_t relo_ip = curr_relo_ip + relo_insn_len;
  int32_t new_offset = orig_dst_ip - relo_ip;
  buffer->Emit<int32_t>(new_offset);
}

int GenRelocateSingleX86Insn(addr_t curr_orig_ip, addr_t curr_relo_ip, uint8_t *buffer_cursor, AssemblerBase *assembler,
                             CodeMemBuffer *code_buffer, x86_insn_decode_t &insn, int8_t mode) {
#define __ code_buffer->

  int relocated_insn_len = -1;

  x86_options_t conf = {0};
  conf.mode = mode;

  // decode x86/x64 insn
  x86_insn_decode(&insn, (uint8_t *)buffer_cursor, &conf);

  // x86 ip register == next instruction address
  curr_orig_ip = curr_orig_ip + insn.length;

  auto last_relo_offset = code_buffer->buffer_size;

  // Not static: these are per-instruction bookkeeping, and a shared copy would be torn by a
  // second thread installing a hook at the same time.
  auto x86_insn_encode_start = 0;
  auto x86_insn_encoded_len = 0;
  auto x86_insn_encode_begin = [&] { x86_insn_encode_start = code_buffer->buffer_size; };
  auto x86_insn_encode_end = [&] { x86_insn_encoded_len = code_buffer->buffer_size - x86_insn_encode_start; };

  // Dispatch on the shared classifier rather than on primary_opcode directly: primary_opcode
  // holds only the second byte of a two-byte opcode, so 0F 7E (an SSE move) and 7E (a short
  // conditional branch) are indistinguishable here without it.
  const x86_relo_kind_t relo_kind = x86_relo_classify(&insn);

  if (relo_kind == X86_RELO_JCC_REL8) { // jcc rel8
    DEBUG_LOG("[x86 relo] %p: jc rel8", buffer_cursor);

    int8_t offset = insn.immediate;
    addr_t orig_dst_ip = curr_orig_ip + offset;
#if defined(TARGET_ARCH_IA32)
    uint8_t opcode = 0x80 | (insn.primary_opcode & 0x0f);

    x86_insn_encode_begin();
    __ Emit<int8_t>(0x0F);
    __ Emit<int8_t>(opcode);
    emit_rel32_label(code_buffer, x86_insn_encode_start, curr_relo_ip, orig_dst_ip);
#else
    // jcc_true stage 1
    const uint8_t label_jcc_cond_true_stage2 = 2;
    __ Emit<int8_t>(insn.primary_opcode);
    __ Emit<int8_t>(label_jcc_cond_true_stage2);

    // jcc_false
    const uint8_t label_cond_false = 6 + 8;
    __ Emit<int8_t>(0xEB);
    __ Emit<int8_t>(label_cond_false);

    // jcc_true stage 2, jmp to orig dst
    codegen_x64_jmp_absolute_addr(code_buffer, orig_dst_ip);
#endif

  } else if (relo_kind == X86_RELO_JCC_REL32) { // jcc rel32 (0F 80..8F)
    DEBUG_LOG("[x86 relo] %p: jc rel32", buffer_cursor);

    int32_t offset = (int32_t)insn.immediate;
    addr_t orig_dst_ip = curr_orig_ip + offset;
#if defined(TARGET_ARCH_IA32)
    x86_insn_encode_begin();
    __ Emit<int8_t>(0x0F);
    __ Emit<int8_t>(insn.primary_opcode);
    emit_rel32_label(code_buffer, x86_insn_encode_start, curr_relo_ip, orig_dst_ip);
#else
    // Same shape as the rel8 case above: branch over an absolute jump, because the original
    // destination is generally further from the trampoline than any rel32 can reach. The short
    // form of the same condition is 0x70 | cc, where the near form is 0x80 | cc.
    const uint8_t short_opcode = (uint8_t)(0x70 | (insn.primary_opcode & 0x0F));

    // jcc_true stage 1
    const uint8_t label_jcc_cond_true_stage2 = 2;
    __ Emit<int8_t>(short_opcode);
    __ Emit<int8_t>(label_jcc_cond_true_stage2);

    // jcc_false
    const uint8_t label_cond_false = 6 + 8;
    __ Emit<int8_t>(0xEB);
    __ Emit<int8_t>(label_cond_false);

    // jcc_true stage 2, jmp to orig dst
    codegen_x64_jmp_absolute_addr(code_buffer, orig_dst_ip);
#endif

  } else if (mode == 64 && relo_kind == X86_RELO_RIP_RELATIVE) { // RIP
    DEBUG_LOG("[x86 relo] %p: rip", buffer_cursor);

    int32_t orig_disp = insn.operands[1].mem.disp;
    addr_t orig_dst_ip = curr_orig_ip + orig_disp;

    addr_t rip_insn_seq_addr = 0;
    {

      uint32_t jmp_near_range = (uint32_t)2 * 1024 * 1024 * 1024;
      auto blk = gNearMemoryAllocator.allocNearCodeBlock(insn.length + 6 + 8, orig_dst_ip, jmp_near_range);
      auto rip_insn_seq = (addr_t)blk.addr();
      rip_insn_seq_addr = rip_insn_seq;
    }
    // The allocator can come back empty when no free page exists within branch range. Emitting the
    // jump anyway sends the trampoline into an address that was never written, and execution runs
    // off into zeroed memory -- a null dereference inside an anonymous mapping, far from here.
    if (rip_insn_seq_addr == 0) {
      ERROR_LOG("[x86 relo] no near code block for rip-relative insn at %p", buffer_cursor);
      return -1;
    }

    // jmp *(rip) => jmp to [rip insn seq]
    x86_insn_encode_begin();
    __ Emit<int8_t>(0xFF);
    __ Emit<int8_t>(0x25); // ModR/M: 00 100 101
    __ Emit<int32_t>(0);
    __ Emit<int64_t>(rip_insn_seq_addr);
    x86_insn_encode_end();

    {
      auto rip_insn_seq_buffer = CodeMemBuffer();
#define ___ rip_insn_seq_buffer.

      auto rip_insn_req_ip = rip_insn_seq_addr;
      rip_insn_req_ip = rip_insn_req_ip + insn.length; // next insn addr
      int64_t new_disp64 = (int64_t)orig_dst_ip - (int64_t)rip_insn_req_ip;
      // A RIP-relative displacement is 32-bit. If the block the allocator returned is further away
      // than that reaches, truncating silently points the instruction at unrelated memory.
      if (new_disp64 > INT32_MAX || new_disp64 < INT32_MIN) {
        ERROR_LOG("[x86 relo] rip displacement out of range for insn at %p", buffer_cursor);
        return -1;
      }
      int32_t new_disp = (int32_t)new_disp64;

      // keep orig insn opcode
      ___ EmitBuffer(buffer_cursor, insn.displacement_offset);
      ___ Emit<int32_t>(new_disp);
      // keep orig insn immediate
      if (insn.immediate_offset) {
        ___ EmitBuffer((buffer_cursor + insn.immediate_offset), insn.length - insn.immediate_offset);
      }

      // jmp *(rip) => back to relo process
      auto relo_next_ip = curr_relo_ip + x86_insn_encoded_len;
      codegen_x64_jmp_absolute_addr(&rip_insn_seq_buffer, relo_next_ip);

      if (DobbyCodePatch((void *)rip_insn_seq_addr, rip_insn_seq_buffer.buffer,
                         rip_insn_seq_buffer.buffer_size) != 0) {
        ERROR_LOG("[x86 relo] could not write rip insn sequence at %p", (void *)rip_insn_seq_addr);
        return -1;
      }
    }

  } else if (relo_kind == X86_RELO_JMP_REL8) { // jmp rel8
    DEBUG_LOG("[x86 relo] %p: jmp rel8", buffer_cursor);

    int8_t offset = insn.immediate;
    addr_t orig_dst_ip = curr_orig_ip + offset;

#if defined(TARGET_ARCH_IA32)
    x86_insn_encode_begin();
    __ Emit<int8_t>(0xE9);
    emit_rel32_label(code_buffer, x86_insn_encode_start, curr_relo_ip, orig_dst_ip);
#else
    // jmp *(rip)
    codegen_x64_jmp_absolute_addr(code_buffer, orig_dst_ip);
#endif
  } else if (relo_kind == X86_RELO_CALL_JMP_REL32) { // call or jmp rel32
    DEBUG_LOG("[x86 relo] %p:jmp or call rel32", buffer_cursor);

    int32_t offset = insn.immediate;
    addr_t orig_dst_ip = curr_orig_ip + offset;

    assert(insn.immediate_offset == 1);

#if defined(TARGET_ARCH_IA32)
    x86_insn_encode_begin();

    __ EmitBuffer(buffer_cursor, insn.immediate_offset);
    emit_rel32_label(code_buffer, x86_insn_encode_start, curr_relo_ip, orig_dst_ip);
#else
    __ Emit<int8_t>(0xFF);
    if (insn.primary_opcode == 0xE8) {
      // call *(rip + 2)
      __ Emit<int8_t>(0x15); // ModR/M: 00 010 101
      __ Emit<int32_t>(2);

      // jmp 8
      __ Emit<int8_t>(0xEB);
      __ Emit<int8_t>(0x08);

      // dst
      __ Emit<int64_t>(orig_dst_ip);
    } else {
      // jmp *(rip)
      __ Emit<int8_t>(0x25); // ModR/M: 00 100 101
      __ Emit<int32_t>(0);

      // dst
      __ Emit<int64_t>(orig_dst_ip);
    }
#endif
  } else if (relo_kind == X86_RELO_UNSUPPORTED) {
    // LOOP/LOOPcc/JrCXZ: an IP-relative field with no rewrite here. Copying it verbatim would
    // leave the trampoline branching into the original function, so refuse the relocation and let
    // the caller decline the hook. Aborting the process instead would take the guest with it.
    ERROR_LOG("[x86 relo] unsupported ip-relative insn at %p", buffer_cursor);
    return -1;
  } else {
    __ EmitBuffer(buffer_cursor, insn.length);
  }

  // insn -> relocated insn
  {
    int relo_offset = code_buffer->buffer_size;
    int relo_len = relo_offset - last_relo_offset;
    DEBUG_LOG("insn -> relocated insn: %d -> %d", insn.length, relo_len);
  }
  (void)relocated_insn_len;
  return 0;
}

void GenRelocateCodeX86Shared(void *buffer, CodeMemBlock *origin, CodeMemBlock *relocated, bool branch) {
  int expected_relocated_mem_size = 32;
x86_try_again:
  if (!relocated->addr()) {
    auto blk = gMemoryAllocator.allocExecBlock(expected_relocated_mem_size);
    auto relocated_mem = blk.addr();
    if (relocated_mem == 0) {
      return;
    }
    relocated->reset((addr_t)relocated_mem, expected_relocated_mem_size);
  }

  int ret = GenRelocateCodeFixed(buffer, origin, relocated, branch);
  if (ret == -2) {
    // An instruction could not be relocated at all. Leaving the block empty is the signal callers
    // check to refuse the hook.
    relocated->reset(0, 0);
    return;
  }
  if (ret != 0) {
    const int step_size = 16;
    expected_relocated_mem_size += step_size;
    relocated->reset(0, 0);

    goto x86_try_again;
  }
}

#endif
