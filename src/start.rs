//! Startup code.

use alloc::{boxed::Box, vec::Vec};
use core::{intrinsics, marker::PhantomData, ptr};

use crate::{
    c_str::CStr,
    header::{libgen, stdlib},
    ld_so::{self},
    platform::{
        self, Pal, Sys, get_auxvs,
        types::{c_char, c_int},
    },
};

#[repr(C)]
pub struct Stack<'a> {
    argc: isize,
    argv0: *const c_char,
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> Stack<'a> {
    pub fn argc(&self) -> isize {
        self.argc
    }
    pub unsafe fn set_argc(&mut self, new: isize) {
        self.argc = new;
    }
    pub fn argv_raw(&self) -> *const *const c_char {
        ptr::from_ref(&self.argv0)
    }
    pub fn argv_with_last_null(&self) -> &'a [Option<CStr<'a>>] {
        // SAFETY: safe by construction of this struct
        unsafe {
            let raw_cstrs = core::slice::from_raw_parts(
                self.argv_raw(),
                usize::try_from(self.argc).unwrap() + 1,
            );
            CStr::opt_strs_from_raw(raw_cstrs)
        }
    }

    pub fn envp_raw(&self) -> *const *const c_char {
        unsafe { self.argv_raw().offset(self.argc + 1) }
    }
    pub fn envp_with_last_null(&self) -> &'a [Option<CStr<'a>>] {
        let mut count = 0;
        // TODO: use NullTerminated iterator
        let mut base = self.envp_raw();
        while unsafe { !base.read().is_null() } {
            base = unsafe { base.add(1) };
            count += 1;
        }

        // SAFETY: safe by construction of this struct
        unsafe {
            let raw_cstrs = core::slice::from_raw_parts(self.envp_raw(), count + 1);
            CStr::opt_strs_from_raw(raw_cstrs)
        }
    }

    pub fn auxv(&self) -> *const (usize, usize) {
        unsafe {
            let mut envp = self.envp_raw();
            while !(*envp).is_null() {
                envp = envp.add(1);
            }
            envp.add(1).cast::<(usize, usize)>()
        }
    }
}

fn copy_string_array(array_with_nul: &[Option<CStr>]) -> Vec<*mut c_char> {
    let array_without_nul = &array_with_nul[..array_with_nul.len() - 1];
    let mut vec = Vec::with_capacity(array_with_nul.len());
    let mut lengths = Vec::with_capacity(array_without_nul.len());
    let mut size = 0;

    for item in array_without_nul {
        let this_len = item.expect("non-trailing NULL").len() + 1;
        lengths.push(this_len);
        size += this_len;
    }

    // Programs unfortunately rely on the strings being contiguous in memory. For example:
    // https://github.com/libuv/libuv/blob/12d0dd48e3c6baf1e2f0d9f85f11f0ef58285d6f/src/unix/proctitle.c#L87
    let mut offset = 0;
    let buf = Box::leak(vec![0_u8; size].into_boxed_slice());

    for (len, item_opt) in lengths.into_iter().zip(array_without_nul) {
        let item = item_opt.expect("non-trailing NULL");

        let dst = &mut buf[offset..][..len];
        dst.copy_from_slice(item.to_bytes_with_nul());

        vec.push(dst.as_mut_ptr().cast());
        offset += len;
    }
    vec.push(ptr::null_mut());
    vec
}

// Since Redox and Linux are so similar, it is easy to accidentally run a binary from one on the
// other. This will test that the current system is compatible with the current binary
#[unsafe(no_mangle)]
pub unsafe fn relibc_verify_host() {
    if !Sys::verify() {
        intrinsics::abort();
    }
}
#[unsafe(link_section = ".init_array")]
#[used]
static INIT_ARRAY: [extern "C" fn(); 1] = [init_array];

static mut INIT_COMPLETE: bool = false;

#[used]
#[unsafe(no_mangle)]
static mut __relibc_init_environ: *mut *mut c_char = ptr::null_mut();

extern "C" fn init_array() {
    // The thing is that we cannot guarantee if
    // init_array runs first or if relibc_start runs first

    unsafe {
        if INIT_COMPLETE {
            return;
        }
    }

    unsafe {
        if platform::environ.is_null() {
            platform::environ = __relibc_init_environ;
        }
    }

    unsafe {
        crate::pthread::init();
        INIT_COMPLETE = true
    }
}

/// Diagnostics (redox-rpi, T12): the filetable fd is missing from the auxv.
/// Stop with `brk #0x7a` and leave the stack layout in the registers, which
/// the kernel prints: x0 = sp, x1 = argc, x2 = number of env entries,
/// x3 = auxv start as `Stack::auxv` computes it, x4..x17 and x20..x28 =
/// the 23 words from auxv start - 3 words on. Normally the first auxv pair
/// is (45 = AT_REDOX_FILETABLE_FD, fd) and the word before it is the NULL
/// that ends envp.
#[cfg(all(target_os = "redox", target_arch = "aarch64"))]
#[cold]
#[inline(never)]
unsafe fn auxv_dump(sp: *const usize) -> ! {
    unsafe {
        let argc = *sp;
        let mut p = sp.add(1 + argc + 1);
        let mut envc = 0usize;
        while *p != 0 {
            p = p.add(1);
            envc += 1;
        }
        let auxv = p.add(1);
        let w = auxv.sub(3);
        core::arch::asm!(
            "brk #0x7a",
            in("x0") sp, in("x1") argc, in("x2") envc, in("x3") auxv,
            in("x4") *w.add(0), in("x5") *w.add(1), in("x6") *w.add(2),
            in("x7") *w.add(3), in("x8") *w.add(4), in("x9") *w.add(5),
            in("x10") *w.add(6), in("x11") *w.add(7), in("x12") *w.add(8),
            in("x13") *w.add(9), in("x14") *w.add(10), in("x15") *w.add(11),
            in("x16") *w.add(12), in("x17") *w.add(13),
            in("x20") *w.add(14), in("x21") *w.add(15), in("x22") *w.add(16),
            in("x23") *w.add(17), in("x24") *w.add(18), in("x25") *w.add(19),
            in("x26") *w.add(20), in("x27") *w.add(21), in("x28") *w.add(22),
            options(noreturn, nostack),
        );
    }
}
#[cfg(all(target_os = "redox", not(target_arch = "aarch64")))]
unsafe fn auxv_dump(_sp: *const usize) -> ! {
    panic!("no filetable fd present");
}

#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn relibc_start_v1(
    sp: &'static Stack,
    main: unsafe extern "C" fn(
        argc: isize,
        argv: *mut *mut c_char,
        envp: *mut *mut c_char,
    ) -> c_int,
) -> ! {
    unsafe extern "C" {
        static __preinit_array_start: extern "C" fn();
        static __preinit_array_end: extern "C" fn();
        static __init_array_start: extern "C" fn();
        static __init_array_end: extern "C" fn();
    }

    // Ensure correct host system before executing more system calls
    unsafe { relibc_verify_host() };

    #[cfg(target_os = "redox")]
    let thr_fd = redox_rt::proc::FdGuard::new(
        unsafe {
            crate::platform::get_auxv_raw(sp.auxv().cast(), redox_rt::auxv_defs::AT_REDOX_THR_FD)
        }
        .expect("no thread fd present"),
    )
    .to_upper()
    .expect("failed to move thread fd to upper table");

    #[cfg(target_os = "redox")]
    {
        if redox_rt::current_filetable().fd().is_none() {
            let filetable_fd = unsafe {
                crate::platform::get_auxv_raw(
                    sp.auxv().cast(),
                    redox_rt::auxv_defs::AT_REDOX_FILETABLE_FD,
                )
            }
            .unwrap_or_else(|| unsafe { auxv_dump((sp as *const Stack).cast()) });
            let filetable_guard = redox_rt::proc::FdGuard::new(filetable_fd)
                .to_upper()
                .expect("failed to move filetable fd to upper table");
            *redox_rt::current_filetable() = redox_rt::sys::FdTbl::from_binary_fd(filetable_guard)
                .expect("failed to initialize FILETABLE");
        }
    }

    // Initialize TLS, if necessary
    unsafe {
        ld_so::init(
            sp,
            #[cfg(target_os = "redox")]
            thr_fd,
        )
    };

    #[cfg(target_os = "redox")]
    {
        redox_rt::TLS_ACTIVATED.store(true, core::sync::atomic::Ordering::Relaxed);
    }

    let is_dynamically_linked = if let Some(tcb) = unsafe { ld_so::tcb::Tcb::current() } {
        #[cfg(target_os = "redox")]
        redox_rt::signal::setup_sighandler(&tcb.os_specific, true);

        !tcb.linker_ptr.is_null()
    } else {
        false
    };

    // Set up argc and argv
    let argc = sp.argc();
    let argv = sp.argv_with_last_null();
    unsafe { platform::inner_argv.unsafe_set(copy_string_array(argv)) };
    unsafe { platform::argv = platform::inner_argv.unsafe_mut().as_mut_ptr() };
    // Special code for program_invocation_name and program_invocation_short_name
    if let Some(arg) = unsafe { platform::inner_argv.unsafe_ref() }.first() {
        unsafe { platform::program_invocation_name = *arg };
        unsafe { platform::program_invocation_short_name = libgen::basename(*arg) };
    }
    // We check for NULL here since ld.so might already have initialized it for us, and we don't
    // want to overwrite it if constructors in .init_array of dependency libraries have called
    // setenv.
    let envp = sp.envp_with_last_null();
    if unsafe { platform::environ }.is_null() {
        unsafe { platform::OUR_ENVIRON.unsafe_set(copy_string_array(envp)) };
        unsafe { platform::environ = platform::OUR_ENVIRON.unsafe_mut().as_mut_ptr() };
    }

    let auxvs = unsafe { get_auxvs(sp.auxv().cast()) };
    if !is_dynamically_linked {
        unsafe { crate::platform::init(auxvs) };
        init_array();
        if unsafe { crate::platform::logger::init().is_err() } {
            log::error!("Logger has already been initialised");
        }
    }

    // (It would technically have been equally valid to just allow the option to be set to "1".)
    if let Some(opt) = envp
        .iter()
        .filter_map(|x| *x)
        .find_map(|var| var.strip_prefix(b"RELIBC_DEBUG_COMMIT_HASH="))
        && matches!(opt.to_bytes(), b"1" | b"true")
    {
        let commit_hash =
            option_env!("RELIBC_COMMIT_HASH").unwrap_or("(unknown; not set by build.rs)");
        log::info!("Relibc commit hash: {commit_hash}");
    }

    // Run preinit array
    {
        let mut f = core::ptr::from_ref(unsafe { &__preinit_array_start });
        while f < &raw const __preinit_array_end {
            (unsafe { *f })();
            f = unsafe { f.add(1) };
        }
    }

    // Run init array
    {
        let mut f = core::ptr::from_ref(unsafe { &__init_array_start });
        while f < &raw const __init_array_end {
            (unsafe { *f })();
            f = unsafe { f.add(1) };
        }
    }

    // not argv or envp, because programs like bash try to modify this *const* pointer :|
    unsafe { stdlib::exit(main(argc, platform::argv, platform::environ)) };

    unreachable!();
}
