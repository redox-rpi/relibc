use core::{cell::SyncUnsafeCell, mem::offset_of, ptr::NonNull};

use syscall::{data::*, error::*};

use crate::{
    Tcb,
    proc::{FdGuard, FdGuardUpper, ForkArgs, fork_inner},
    signal::{PosixStackt, RtSigarea, SigStack, inner_c},
};
use redox_protocols::protocol::{ProcCall, RtSigInfo};

use super::ForkScratchpad;

// Setup a stack starting from the very end of the address space, and then growing downwards.
pub const STACK_TOP: usize = 1 << 47;
pub const STACK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Default)]
#[repr(C)]
pub struct SigArea {
    pub altstack_top: usize,
    pub altstack_bottom: usize,
    /// x1-x8 and sp of the interrupted code while the signal entry picks a
    /// signal; only these fields of `tmp` are used.
    pub tmp: ArchIntRegs,
    pub onstack: u64,
    pub disable_signals_depth: u64,
    pub pctl: usize, // TODO: remove
    pub last_sig_was_restart: bool,
    pub last_sigstack: Option<NonNull<SigStack>>,
    pub tmp_rt_inf: RtSigInfo,
    pub tmp_id_inf: u64,
}
#[repr(C)]
#[derive(Debug, Default)]
pub struct ArchIntRegs {
    pub x30: usize,
    pub x29: usize,
    pub x28: usize,
    pub x27: usize,
    pub x26: usize,
    pub x25: usize,
    pub x24: usize,
    pub x23: usize,
    pub x22: usize,
    pub x21: usize,
    pub x20: usize,
    pub x19: usize,
    pub x18: usize,
    pub x17: usize,
    pub x16: usize,
    pub x15: usize,
    pub x14: usize,
    pub x13: usize,
    pub x12: usize,
    pub x11: usize,
    pub x10: usize,
    pub x9: usize,
    pub x8: usize,
    pub x7: usize,
    pub x6: usize,
    pub x5: usize,
    pub x4: usize,
    pub x3: usize,
    pub x2: usize,
    pub x1: usize,

    pub sp: usize,
    pub nzcv: usize, // user-accessible PSTATE bits

    pub pc: usize,
    pub x0: usize,
}

/// Deactive TLS, used before exec() on Redox to not trick target executable into thinking TLS
/// is already initialized as if it was a thread.
pub unsafe fn deactivate_tcb(open_via_dup: &FdGuardUpper) -> Result<()> {
    let mut env = syscall::EnvRegisters::default();

    let file = open_via_dup.dup_into_upper(b"regs/env")?;

    env.tpidr_el0 = 0;

    file.write(&env)?;
    crate::TLS_ACTIVATED.store(false, core::sync::atomic::Ordering::Relaxed);
    Ok(())
}

unsafe extern "C" fn fork_impl(args: &ForkArgs, initial_rsp: *mut usize) -> usize {
    Error::mux(fork_inner(initial_rsp, args))
}

unsafe extern "C" fn child_hook(scratchpad: &ForkScratchpad) {
    //let _ = syscall::write(1, alloc::format!("CUR{cur_filetable_fd}PROC{new_proc_fd}THR{new_thr_fd}\n").as_bytes());
    let _ = crate::sys::close(scratchpad.cur_filetable_fd);
    unsafe {
        crate::child_hook_common(crate::ChildHookCommonArgs {
            new_thr_fd: FdGuard::new(scratchpad.new_thr_fd),
            new_proc_fd: if scratchpad.new_proc_fd == usize::MAX {
                None
            } else {
                Some(FdGuard::new(scratchpad.new_proc_fd))
            },
            new_filetable_fd: FdGuard::new(scratchpad.new_filetable_fd)
                .to_upper()
                .unwrap(),
        })
    };
}

asmfunction!(__relibc_internal_fork_wrapper (usize) -> usize: ["
    // The callee-saved part of the floating point registers, d8-d15, goes on
    // the stack with the integer registers, so that the child, which starts
    // at __relibc_internal_fork_ret on a copy of this stack, gets them too.
    // Otherwise the child continues with whatever these registers held on
    // its CPU, and corrupts values the compiler kept in them across the call.
    stp     d14, d15, [sp, #-16]!
    stp     d12, d13, [sp, #-16]!
    stp     d10, d11, [sp, #-16]!
    stp     d8, d9, [sp, #-16]!
    stp     x29, x30, [sp, #-16]!
    stp     x27, x28, [sp, #-16]!
    stp     x25, x26, [sp, #-16]!
    stp     x23, x24, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x19, x20, [sp, #-16]!

    // x0: &ForkArgs
    mov x1, sp
    bl {fork_impl}

    ldp     x19, x20, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x27, x28, [sp], #16
    ldp     x29, x30, [sp], #16
    ldp     d8, d9, [sp], #16
    ldp     d10, d11, [sp], #16
    ldp     d12, d13, [sp], #16
    ldp     d14, d15, [sp], #16
    ret
"] <= [fork_impl = sym fork_impl]);

asmfunction!(__relibc_internal_fork_ret: ["
    # scratchpad is in x1, move to x0 for child_hook
    mov x0, x1

    bl {child_hook}

    mov x0, xzr

    ldp     x19, x20, [sp], #16
    ldp     x21, x22, [sp], #16
    ldp     x23, x24, [sp], #16
    ldp     x25, x26, [sp], #16
    ldp     x27, x28, [sp], #16
    ldp     x29, x30, [sp], #16
    ldp     d8, d9, [sp], #16
    ldp     d10, d11, [sp], #16
    ldp     d12, d13, [sp], #16
    ldp     d14, d15, [sp], #16

    ret
"] <= [child_hook = sym child_hook]);

/// Floating point and SIMD registers as the signal entry saves them, right
/// above the `SigStack` on the stack.
#[repr(C)]
pub struct ArchFpRegs {
    pub q: [u128; 32],
    pub fpcr: usize,
    pub fpsr: usize,
}

/// One load or store per register, each at the offset of the field with the
/// same name: `each_reg!("str", "sp, #"; x9 x10)` becomes
/// `str x9, [sp, #{x9}]` and `str x10, [sp, #{x10}]`, where the operand
/// `{x9}` is `offset_of!(ArchIntRegs, x9)`. So a register can only go into
/// its own field, whatever the order of the fields.
macro_rules! each_reg {
    ($op:literal, $base:literal; $($reg:ident)*) => {
        concat!($(
            "    ", $op, " ", stringify!($reg), ", [", $base, "{", stringify!($reg), "}]\n",
        )*)
    };
}

/// Copies fields from one `ArchIntRegs` to another through x2.
macro_rules! copy_regs {
    ($from:literal => $to:literal; $($reg:ident)*) => {
        concat!($(
            "    ldr x2, [", $from, "{", stringify!($reg), "}]\n",
            "    str x2, [", $to, "{", stringify!($reg), "}]\n",
        )*)
    };
}

/// Defines `__relibc_internal_sigentry`. `$reg` are the registers that the
/// signal entry keeps untouched until it saves them into the `ArchIntRegs`
/// and that it restores last; it saves and restores them from this one list.
macro_rules! sigentry {
    ($($reg:ident)*) => {
// https://devblogs.microsoft.com/oldnewthing/20220811-00/?p=106963
asmfunction!(__relibc_internal_sigentry: ["
    // Clear any active reservation.
    clrex

    // The old pc and x0 are saved in the sigcontrol struct.
    mrs x0, tpidr_el0 // ABI ptr
    ldr x0, [x0] // TCB ptr

    // Save x1-x8 and sp in the TCB: the code below uses them to pick a
    // signal.
",
    each_reg!("str", "x0, #{tcb_sa_off} + {sa_tmp} + "; x1 x2 x3 x4 x5 x6 x7 x8),
"
    mov x1, sp
    str x1, [x0, #{tcb_sa_off} + {sa_tmp} + {sp}]

    ldr x6, [x0, #{tcb_sa_off} + {sa_pctl}]
1:
    // Load x1 with the thread's bits
    add x5, x0, #{tcb_sc_off} + {sc_word}
    ldaxr x1, [x5]

    // First check if there are standard thread signals,
    and x4, x1, x1, lsr #32 // x4 := x1 & (x1 >> 32)
    cbnz x4, 3f // jump if x4 != 0
    clrex

    // and if not, load process pending bitset.
    add x5, x6, #{pctl_pending}
    ldaxr x2, [x5]

    // Check if there are standard proc signals:
    lsr x3, x1, #32 // mask
    and w3, w2, w3 // pending unblocked proc
    cbz w3, 4f // skip 'fetch_andn' step if zero

    // If there was one, find which one, and try clearing the bit (last value in x3, addr in x6)
    // this picks the MSB rather than the LSB, unlike x86. POSIX does not require any specific
    // ordering though.
    clz w3, w3
    mov w4, #31
    sub w3, w4, w3
    // x3 now contains the sig_idx

    mov x4, #1
    lsl x4, x4, x3 // bit to remove

    sub x4, x2, x4 // bit was certainly set, so sub is allowed
    // x4 is now the new mask to be set
    add x5, x6, #{pctl_pending}

    add x2, x5, #{pctl_sender_infos}
    add x2, x2, w3, uxtb 3
    ldar x2, [x2]

    // Try clearing the bit, retrying on failure.
    stxr w1, x4, [x5] // try setting pending set to x4, set w1 := 0 on success
    cbnz w1, 1b // retry everything if this fails
    mov x1, x3
    b 2f
4:
    // Check for realtime signals, thread/proc.
    clrex

    // Load the pending set again. TODO: optimize this?
    // Process pending - realtime
    add x1, x6, #{pctl_pending}
    ldaxr x2, [x1]
    lsr x2, x2, #32

    // Thread pending - realtime and allowset
    add x5, x0, #{tcb_sc_off} + {sc_word} + 8
    ldar x1, [x5]

    orr x2, x1, x2 // combine proc and thread pending
    and x2, x2, x2, lsr #32 // AND pending with allowset
    cbz x2, 7f // spurious signal if realtime is clear

    rbit x2, x2
    clz x2, x2
    // x2 now contains sig_idx - 32

    // If realtime signal was directed at thread, handle it as an idempotent signal.
    lsr x3, x1, x2 // x3 := x1 >> x2; x1 is thread pending
    tbnz x3, #0, 5f // jump if bit is nonzero

    // SYS_CALL(fd, payload_base, payload_len, metadata_len, metadata_base | (flags << 8))
    // x8       x0  x1            x2           x3            x4

    mov x5, x0 // save TCB pointer
    mov x6, x2
    ldr x8, ={SYS_CALL}
    adrp x0, {proc_fd}
    ldr x0, [x0, #:lo12:{proc_fd}]
    add x1, x5, #{tcb_sa_off} + {sa_tmp_rt_inf}
    str x6, [x1]
    mov x2, #{RTINF_SIZE}
    adrp x4, {proc_call}
    add x4, x4, :lo12:{proc_call}
    mov x3, #1
    svc 0
    mov x3, x0
    mov x0, x5 // restore TCB pointer
    mov x2, x6 // restore signal number - 32
    add x1, x2, #32 // signal number
    cbnz x3, 1b
    b 2f
5:
    // A realtime signal was sent to this thread, try clearing its bit.
    // x3 contains last rt signal word, x2 contains rt_idx
    clrex

    // Calculate the absolute sig_idx
    add x1, x3, 32

    // Load si_pid and si_uid
    add x2, x0, #{tcb_sc_off} + {sc_sender_infos}
    add x2, x2, w1, uxtb #3
    ldar x2, [x2]

    add x3, x0, #{tcb_sc_off} + {sc_word} + 8
    ldxr x2, [x3]

    // Calculate new mask
    mov x4, #1
    lsl x4, x4, x2
    sub x2, x2, x4 // remove bit

    stxr w5, x2, [x3]
    cbnz w5, 1b
    str x2, [x0, #{tcb_sa_off} + {sa_tmp_id_inf}]
    b 2f
3:
    // A standard signal was sent to this thread, try clearing its bit.
    clz w1, w1
    mov x2, #31
    sub x1, x2, x1

    // Load si_pid and si_uid
    add x2, x0, #{tcb_sc_off} + {sc_sender_infos}
    add x2, x2, w1, uxtb #3
    ldar x2, [x2]

    // Clear bit from mask
    mov x3, #1
    lsl x3, x3, x1
    sub x4, x4, x3

    // Try updating the mask
    stxr w3, x1, [x5]
    cbnz w3, 1b

    str x2, [x0, #{tcb_sa_off} + {sa_tmp_id_inf}]
2:
    ldr x3, [x0, #{tcb_sa_off} + {sa_pctl}]
    add x3, x3, {pctl_actions}
    add x2, x3, w1, uxtb #4 // actions_base + sig_idx * sizeof Action
    // TODO: NOT ATOMIC (tearing allowed between regs)!
    ldxp x2, x3, [x2]
    clrex

    // Calculate new sp wrt redzone and alignment
    mov x4, sp
    sub x4, x4, {REDZONE_SIZE}
    and x4, x4, -{STACK_ALIGN}
    mov sp, x4

    // Save the floating point and SIMD registers above the integer
    // registers (ArchFpRegs): the Rust code below uses q0-q31 freely
    // (memcpy, struct copies), and the interrupted code expects them
    // unchanged. x86_64 does the same with fxsave64. x2 and x3 are free here.
    mrs x2, fpcr
    mrs x3, fpsr
    stp x2, x3, [sp, #-16]!
    stp q30, q31, [sp, #-32]!
    stp q28, q29, [sp, #-32]!
    stp q26, q27, [sp, #-32]!
    stp q24, q25, [sp, #-32]!
    stp q22, q23, [sp, #-32]!
    stp q20, q21, [sp, #-32]!
    stp q18, q19, [sp, #-32]!
    stp q16, q17, [sp, #-32]!
    stp q14, q15, [sp, #-32]!
    stp q12, q13, [sp, #-32]!
    stp q10, q11, [sp, #-32]!
    stp q8, q9, [sp, #-32]!
    stp q6, q7, [sp, #-32]!
    stp q4, q5, [sp, #-32]!
    stp q2, q3, [sp, #-32]!
    stp q0, q1, [sp, #-32]!

    // skip sigaltstack step if SA_ONSTACK is clear
    // tbz x2, #{SA_ONSTACK_BIT}, 2f

    // Below them the SigStack, which inner_c gets. Every register goes into
    // the ArchIntRegs field of its own name (SigStack::regs).
    sub sp, sp, #{ss_size}
    str w1, [sp, #{ss_sig_num}]
",
    each_reg!("str", "sp, #{ss_regs} + "; $($reg)*),
    copy_regs!("x0, #{tcb_sa_off} + {sa_tmp} + " => "sp, #{ss_regs} + "; x1 x2 x3 x4 x5 x6 x7 x8 sp),
"
    ldr x2, [x0, #{tcb_sc_off} + {sc_saved_pc}]
    str x2, [sp, #{ss_regs} + {pc}]
    ldr x2, [x0, #{tcb_sc_off} + {sc_saved_x0}]
    str x2, [sp, #{ss_regs} + {x0}]
    mrs x2, nzcv
    str x2, [sp, #{ss_regs} + {nzcv}]

    mov x0, sp
    bl {inner}

    // Restore from the same fields. x18 is reserved by the ABI as 'platform
    // register', so clobbering it should be safe: it holds the address of
    // the ArchIntRegs until the jump back.
    add x18, sp, #{ss_regs}
",
    each_reg!("ldr", "x18, #"; $($reg)*),
    each_reg!("ldr", "x18, #"; x1 x2 x3 x4 x5 x6 x7 x8),
"
    ldr x0, [x18, #{nzcv}]
    msr nzcv, x0

    // The floating point and SIMD registers, right above the SigStack.
    add x0, x18, #{int_regs_size}
    ldp q0, q1, [x0], #32
    ldp q2, q3, [x0], #32
    ldp q4, q5, [x0], #32
    ldp q6, q7, [x0], #32
    ldp q8, q9, [x0], #32
    ldp q10, q11, [x0], #32
    ldp q12, q13, [x0], #32
    ldp q14, q15, [x0], #32
    ldp q16, q17, [x0], #32
    ldp q18, q19, [x0], #32
    ldp q20, q21, [x0], #32
    ldp q22, q23, [x0], #32
    ldp q24, q25, [x0], #32
    ldp q26, q27, [x0], #32
    ldp q28, q29, [x0], #32
    ldp q30, q31, [x0], #32
    ldr x0, [x18, #{int_regs_size} + {fp_fpcr}]
    msr fpcr, x0
    ldr x0, [x18, #{int_regs_size} + {fp_fpsr}]
    msr fpsr, x0

    ldr x0, [x18, #{sp}]
    mov sp, x0
    ldr x0, [x18, #{x0}]
    ldr x18, [x18, #{pc}]
    br x18
7:
    // Spurious signal, i.e. all bitsets were 0 at the time they were checked
    clrex

    ldr x1, [x0, #{tcb_sc_off} + {sc_flags}]
    and x1, x1, ~1
    str x1, [x0, #{tcb_sc_off} + {sc_flags}]
",
    each_reg!("ldr", "x0, #{tcb_sa_off} + {sa_tmp} + "; x1 x2 x3 x4 x5 x6 x7 x8),
"
    ldr x18, [x0, #{tcb_sc_off} + {sc_saved_pc}]
    ldr x0, [x0, #{tcb_sc_off} + {sc_saved_x0}]
    br x18
"] <= [
    pctl_pending = const (offset_of!(SigProcControl, pending)),
    pctl_actions = const (offset_of!(SigProcControl, actions)),
    pctl_sender_infos = const (offset_of!(SigProcControl, sender_infos)),
    tcb_sc_off = const (offset_of!(crate::Tcb, os_specific) + offset_of!(RtSigarea, control)),
    tcb_sa_off = const (offset_of!(crate::Tcb, os_specific) + offset_of!(RtSigarea, arch)),
    sa_tmp = const offset_of!(SigArea, tmp),
    sa_tmp_rt_inf = const offset_of!(SigArea, tmp_rt_inf),
    sa_tmp_id_inf = const offset_of!(SigArea, tmp_id_inf),
    sa_pctl = const offset_of!(SigArea, pctl),
    sc_saved_pc = const offset_of!(Sigcontrol, saved_ip),
    sc_saved_x0 = const offset_of!(Sigcontrol, saved_archdep_reg),
    sc_sender_infos = const offset_of!(Sigcontrol, sender_infos),
    sc_word = const offset_of!(Sigcontrol, word),
    sc_flags = const offset_of!(Sigcontrol, control_flags),
    ss_size = const size_of::<SigStack>(),
    ss_regs = const offset_of!(SigStack, regs),
    ss_sig_num = const offset_of!(SigStack, sig_num),
    int_regs_size = const size_of::<ArchIntRegs>(),
    fp_fpcr = const offset_of!(ArchFpRegs, fpcr),
    fp_fpsr = const offset_of!(ArchFpRegs, fpsr),
    x0 = const offset_of!(ArchIntRegs, x0),
    x1 = const offset_of!(ArchIntRegs, x1),
    x2 = const offset_of!(ArchIntRegs, x2),
    x3 = const offset_of!(ArchIntRegs, x3),
    x4 = const offset_of!(ArchIntRegs, x4),
    x5 = const offset_of!(ArchIntRegs, x5),
    x6 = const offset_of!(ArchIntRegs, x6),
    x7 = const offset_of!(ArchIntRegs, x7),
    x8 = const offset_of!(ArchIntRegs, x8),
    sp = const offset_of!(ArchIntRegs, sp),
    nzcv = const offset_of!(ArchIntRegs, nzcv),
    pc = const offset_of!(ArchIntRegs, pc),
    proc_fd = sym PROC_FD,
    inner = sym inner_c,
    proc_call = sym PROC_CALL,

    SA_ONSTACK_BIT = const 58, // (1 << 58) >> 32 = 0x0400_0000

    SYS_CALL = const syscall::SYS_CALL,

    STACK_ALIGN = const 16,
    REDZONE_SIZE = const 128,
    RTINF_SIZE = const size_of::<RtSigInfo>(),
    $($reg = const offset_of!(ArchIntRegs, $reg)),*
]);
    };
}

// x18 is left out: the restore needs it as the base register.
sigentry!(x9 x10 x11 x12 x13 x14 x15 x16 x17 x19 x20 x21 x22 x23 x24 x25 x26 x27 x28 x29 x30);

// The pushes in the signal entry give exactly this layout.
const _: () = assert!(size_of::<ArchFpRegs>() == 32 * 16 + 16);

asmfunction!(__relibc_internal_rlct_clone_ret: ["
    # Load registers
    ldp x8, x0, [sp], #16
    ldp x1, x2, [sp], #16
    ldp x3, x4, [sp], #16

    # Call entry point
    blr x8

    ret
"] <= []);

pub fn current_sp() -> usize {
    let sp: usize;
    unsafe {
        core::arch::asm!("mov {}, sp", out(reg) sp);
    }
    sp
}

pub unsafe fn manually_enter_trampoline() {
    let ctl = unsafe { &Tcb::current().unwrap().os_specific.control };

    ctl.saved_archdep_reg.set(0);
    let ip_location = &raw const ctl.saved_ip as usize;

    unsafe {
        core::arch::asm!("
                bl 2f
                b 3f
            2:
                str lr, [x0]
                b __relibc_internal_sigentry
            3:
            ",
            inout("x0") ip_location => _, out("lr") _);
    }
}

#[expect(unused_variables, reason = "function not yet fully implemented")]
pub unsafe fn arch_pre(stack: &mut SigStack, os: &mut SigArea) -> PosixStackt {
    PosixStackt {
        sp: core::ptr::null_mut(), // TODO
        size: 0,                   // TODO
        flags: 0,                  // TODO
    }
}
/// map to `si_signo` and `si_code`.
pub(crate) fn map_err_code(_excp: &syscall::Exception) -> (i32, i32) {
    use redox_protocols::flag::*;
    (SIGABRT, 0 /* todo */)
}
pub fn arch_ret_to_sig(stack: &mut SigStack, control: &Sigcontrol) {
    let orig_pc = core::mem::replace(
        &mut stack.regs.pc,
        __relibc_internal_sigentry as *const () as usize,
    );
    control.saved_ip.set(orig_pc);
    control.saved_archdep_reg.set(stack.regs.x0);
}
pub(crate) static PROC_FD: SyncUnsafeCell<usize> = SyncUnsafeCell::new(usize::MAX);
static PROC_CALL: [usize; 1] = [ProcCall::Sigdeq as usize];
