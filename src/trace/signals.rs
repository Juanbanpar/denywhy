use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

static SIGNALS: AtomicU32 = AtomicU32::new(0);
extern "C" fn remember(signal: i32) {
    SIGNALS.fetch_or(1 << signal, Ordering::Relaxed);
}

pub fn install() -> io::Result<[libc::sigaction; 3]> {
    // Each array element is writable POD storage for an old sigaction.
    let mut old: [libc::sigaction; 3] = unsafe { std::mem::zeroed() };
    // sigaction is a POD C structure. A zero mask excludes no additional signals,
    // and no SA_RESTART means waitpid wakes to forward an incoming signal.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = remember as *const () as usize;
    for (index, signal) in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
        .into_iter()
        .enumerate()
    {
        // The action is live and correctly initialized; old[index] is writable storage for the previous disposition.
        if unsafe { libc::sigaction(signal, &action, &mut old[index]) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(old)
}
pub fn reset_child(old: &[libc::sigaction; 3]) {
    // A default sigaction has no handler or mask. Restore wrapper-installed
    // handlers before the child stops so startup signals retain their meaning.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    for (index, signal) in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGPIPE]
        .into_iter()
        .enumerate()
    {
        action.sa_sigaction = if index < old.len() && old[index].sa_sigaction == libc::SIG_IGN {
            libc::SIG_IGN
        } else {
            libc::SIG_DFL
        };
        // action stays live for each kernel copy; errors are handled by child termination.
        unsafe {
            if libc::sigaction(signal, &action, std::ptr::null_mut()) < 0 {
                libc::_exit(125);
            }
        }
    }
}
pub fn forward(tids: impl Iterator<Item = i32>) {
    let signals = SIGNALS.swap(0, Ordering::Relaxed);
    if signals == 0 {
        return;
    }
    for tid in tids {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            if signals & (1 << signal) != 0 {
                // TIDs came from waitpid/ptrace events. Exited threads may yield ESRCH.
                unsafe {
                    libc::syscall(libc::SYS_tkill, tid, signal);
                }
            }
        }
    }
}
