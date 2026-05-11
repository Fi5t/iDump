// Advanced anti-Frida bypass agent.
//
// Targets hardened apps that:
//   1. Issue raw syscalls (SYS_ptrace / SYS_sysctl / SYS_connect / SYS_stat)
//      to bypass libc symbol hooks.
//   2. Walk environ[] directly instead of calling getenv().
//   3. Read dyld_all_image_infos.infoArray and thread_info(THREAD_EXTENDED_INFO)
//      directly via Mach APIs rather than going through libc wrappers.
//   4. Probe TCP 127.0.0.1:27042 over both IPv4 *and* IPv6.
//   5. Scan non-writable VM regions for "frida-agent" / "FridaGadget" byte
//      sequences via vm_region_recurse_64 + memcmp.
//   6. Audit a fixed set of libc symbols (sysctl, connect, stat, getenv,
//      pthread_getname_np, _dyld_get_image_name, task_get_exception_ports)
//      for branch-instruction prologues to detect Interceptor.attach.
//
// Defense layers (top is the primary; the rest are defense-in-depth):
//   A. Patch the public detector entry points (fd_full_checks, fd_early_checks)
//      to RET. These are not in the audit list — neutralising them silences
//      every check they dispatch (8 of 11 vectors).
//   B. The remaining 3 vectors (fd_ptrace_deny, fd_check_sysctl, fd_check_env)
//      run from a dyld constructor *before* App.init() is reached, so they
//      cannot rely on fd_full_checks. They are handled by:
//        - hooking the libc `syscall` multiplexer (covers SYS_ptrace + SYS_sysctl)
//        - rewriting the DYLD_INSERT_LIBRARIES key in environ[] in place
//   C. Backstop hooks on libsystem_kernel thunks (__sysctl, __connect, __stat*),
//      task_info / thread_info / vm_region_recurse_64, and a GOT redirect for
//      task_get_exception_ports — useful if symbol stripping prevents (A) from
//      finding fd_full_checks on a future build.
//
// CRITICAL INVARIANT: this agent must NOT install Interceptor hooks on any of
// the 7 audited symbols above. All defenses go through libsystem_kernel
// thunks, the libc syscall() multiplexer, Mach-level APIs the audit does not
// scan, GOT pointer rewrites in the app binary, or direct prologue patching
// of detector functions that are not in the audit list.

const FORBIDDEN_HOOK_SYMBOLS = [
    "sysctl",
    "connect",
    "stat",
    "getenv",
    "pthread_getname_np",
    "_dyld_get_image_name",
    "task_get_exception_ports",
];

// Darwin syscall numbers (sys/syscall.h, stable across iOS releases).
const SYS_ptrace = 26;
const SYS_connect = 98;
const SYS_stat = 188;
const SYS_lstat = 190;
const SYS_sysctl = 202;
const SYS_stat64 = 338;

const CTL_KERN = 1;
const KERN_PROC = 14;
const P_TRACED = 0x00000800;

const AF_INET = 2;
const AF_INET6 = 30; // Darwin value (Linux uses 10).

const FRIDA_PORT = 27042;

const TASK_DYLD_INFO = 17;
const THREAD_EXTENDED_INFO = 5;

const VM_PROT_WRITE = 0x02;

const MACH_PORT_NULL = 0;

const DYLD_INSERT_KEY = "DYLD_INSERT_LIBRARIES";
const FRIDA_THREAD_NAMES = ["gum-js-loop", "gmain", "pool-frida"];
const FRIDA_PATH_NEEDLES = ["frida", "FridaGadget", "gadget", "cynict"];
const FRIDA_DYLIB_NEEDLES = ["frida", "FridaGadget", "frida-agent", "frida_agent"];

const ARM64_RET = 0xd65f03c0;

const libKernel = Process.findModuleByName("libsystem_kernel.dylib");
const libC = Process.findModuleByName("libsystem_c.dylib");
const libPthread = Process.findModuleByName("libsystem_pthread.dylib");

// Locate the real main executable. On jailbroken devices the first
// enumerated module is often a tweak loader (e.g. systemhook.dylib); the
// detector lives in the module whose Mach-O header has filetype == MH_EXECUTE.
function findMainExecutable(): Module | null {
    const MH_EXECUTE = 2;
    for (const m of Process.enumerateModules()) {
        try {
            if (m.base.add(12).readU32() === MH_EXECUTE) return m;
        } catch {
            // unreadable header; skip
        }
    }
    return null;
}

const mainModule = findMainExecutable();
const mainBase = mainModule ? mainModule.base : ptr(0);
const mainEnd = mainModule ? mainModule.base.add(mainModule.size) : ptr(0);

// fromApp — true if `retAddr` lies inside the main executable. Used to gate
// Mach-API hooks so they only mutate output for app-side callers; Frida's own
// runtime calls these APIs too and breaks if its results are sanitised.
function fromApp(retAddr: NativePointer | undefined): boolean {
    if (!retAddr || !mainModule) return false;
    return retAddr.compare(mainBase) >= 0 && retAddr.compare(mainEnd) < 0;
}

function kernelExport(name: string): NativePointer | null {
    return libKernel ? libKernel.findExportByName(name) : null;
}

function libcExport(name: string): NativePointer | null {
    return libC ? libC.findExportByName(name) : null;
}

// findSym — search likely modules in order, then fall back to a full scan.
// Many "libc" symbols actually live in libsystem_kernel.dylib on iOS; e.g.
// `syscall` is exported from libsystem_kernel, not libsystem_c.
function findSym(name: string): NativePointer | null {
    for (const mod of [libKernel, libC, libPthread]) {
        if (!mod) continue;
        const p = mod.findExportByName(name);
        if (p) return p;
    }
    try {
        for (const mod of Process.enumerateModules()) {
            const p = mod.findExportByName(name);
            if (p) return p;
        }
    } catch {
        // ignore
    }
    return null;
}

function containsAny(haystack: string, needles: string[]): boolean {
    const lower = haystack.toLowerCase();
    return needles.some((n) => lower.indexOf(n.toLowerCase()) >= 0);
}

// ---------------------------------------------------------------------------
// (A) Patch fd_full_checks / fd_early_checks to RET
// ---------------------------------------------------------------------------
// These are the public entry points that drive every periodic detection
// vector. Neither name appears in fd_check_hooks's audit list, so writing a
// RET into the prologue silences the detector without tripping the scanner.

function findInMainModule(name: string): NativePointer | null {
    if (!mainModule) return null;
    const exp = mainModule.findExportByName(name);
    if (exp) return exp;
    try {
        for (const s of mainModule.enumerateSymbols()) {
            if (s.name === name || s.name === "_" + name) return s.address;
        }
    } catch {
        // ignore
    }
    try {
        const ds = DebugSymbol.fromName(name);
        if (ds && !ds.address.isNull()) return ds.address;
    } catch {
        // ignore
    }
    return null;
}

function neutraliseDetectorEntry(name: string): boolean {
    const p = findInMainModule(name);
    if (!p) return false;
    try {
        Memory.patchCode(p, 4, (code) => code.writeU32(ARM64_RET));
        return true;
    } catch {
        return false;
    }
}

// ---------------------------------------------------------------------------
// (B1) environ scrub — defeats fd_check_env from the dyld constructor
// ---------------------------------------------------------------------------
// fd_check_env walks environ[] for "DYLD_INSERT_LIBRARIES=...". Overwriting
// the second byte from 'Y' to '_' makes the strncmp fail without changing
// the entry's length or position.

function scrubEnviron(): boolean {
    const nsEnvironPtr = libcExport("_NSGetEnviron");
    if (!nsEnvironPtr) return false;
    const fn = new NativeFunction(nsEnvironPtr, "pointer", []);
    const envPtrPtr = fn() as NativePointer;
    if (envPtrPtr.isNull()) return false;
    let environ = envPtrPtr.readPointer();
    if (environ.isNull()) return false;

    const keyLen = DYLD_INSERT_KEY.length; // 21
    let scrubbed = false;
    while (true) {
        const entry = environ.readPointer();
        if (entry.isNull()) break;
        try {
            const head = entry.readCString(keyLen + 1) ?? "";
            if (head.length >= keyLen + 1 && head.startsWith(DYLD_INSERT_KEY) && head.charAt(keyLen) === "=") {
                entry.add(1).writeU8(0x5f); // 'Y' -> '_'
                scrubbed = true;
            }
        } catch {
            // ignore unreadable entry
        }
        environ = environ.add(Process.pointerSize);
    }
    return scrubbed;
}

// ---------------------------------------------------------------------------
// (C1) GOT redirect for task_get_exception_ports
// ---------------------------------------------------------------------------
// fd_check_exception_ports calls task_get_exception_ports and terminates if
// the returned count is zero or any handler is MACH_PORT_VALID. The public
// symbol is in the audit list, so we cannot Interceptor.attach it. Instead
// we patch the app binary's GOT slot for that import, redirecting only the
// app's call sites. dlsym(RTLD_DEFAULT, "task_get_exception_ports") still
// resolves to the unmodified libsystem_kernel symbol — fd_is_patched sees
// pristine bytes.

function installExceptionPortsRedirect(): number {
    if (!mainModule) return 0;

    // Stub: succeed, claim 1 mask slot, all handlers == MACH_PORT_NULL.
    const stub = new NativeCallback(
        (
            _task: number,
            _exceptionMask: number,
            masks: NativePointer,
            masksCntPtr: NativePointer,
            handlers: NativePointer,
            behaviors: NativePointer,
            flavors: NativePointer,
        ) => {
            try {
                if (!masksCntPtr.isNull()) masksCntPtr.writeU32(1);
                if (!masks.isNull()) masks.writeU32(0);
                if (!handlers.isNull()) handlers.writeU32(MACH_PORT_NULL);
                if (!behaviors.isNull()) behaviors.writeU32(0);
                if (!flavors.isNull()) flavors.writeU32(0);
            } catch {
                // ignore
            }
            return 0; // KERN_SUCCESS
        },
        "int",
        ["uint", "int", "pointer", "pointer", "pointer", "pointer", "pointer"],
    );

    let patched = 0;
    try {
        for (const imp of mainModule.enumerateImports()) {
            if (imp.name !== "task_get_exception_ports") continue;
            const slot = (imp as { slot?: NativePointer }).slot;
            if (!slot || slot.isNull()) continue;
            try {
                // The slot lives in __DATA_CONST (read-only after dyld's
                // chained-fixup binding). Flip the page to RW, write, restore.
                const pageSize = Process.pageSize;
                const offsetInPage = slot.toInt32() & (pageSize - 1);
                const pageBase = slot.sub(offsetInPage);
                Memory.protect(pageBase, pageSize, "rw-");
                slot.writePointer(stub);
                Memory.protect(pageBase, pageSize, "r--");
                patched++;
            } catch {
                // ignore
            }
        }
    } catch {
        // ignore
    }
    return patched;
}

// ---------------------------------------------------------------------------
// (B2) syscall multiplexer hook — defeats SYS_ptrace, SYS_sysctl, SYS_connect,
// SYS_stat etc. issued via libc's varargs `syscall()`. Not in the audit list.

function rewriteSockaddrPort(addr: NativePointer): void {
    if (addr.isNull()) return;
    try {
        const family = addr.add(1).readU8();
        if (family === AF_INET || family === AF_INET6) {
            // sin_port and sin6_port both at offset 2 (network byte order).
            const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
            if (port === FRIDA_PORT) {
                addr.add(2).writeU8(0x00);
                addr.add(3).writeU8(0x01);
            }
        }
    } catch {
        // ignore unreadable sockaddr
    }
}

function rewriteFridaPath(arg: NativePointer): void {
    try {
        const p = arg.readCString();
        if (p && containsAny(p, FRIDA_PATH_NEEDLES)) {
            arg.writePointer(Memory.allocUtf8String("/nonexistent_frida_probe"));
        }
    } catch {
        // ignore
    }
}

const syscallPtr = findSym("syscall");
if (syscallPtr) {
    Interceptor.attach(syscallPtr, {
        onEnter(args) {
            const nr = args[0].toInt32();
            this.nr = nr;

            switch (nr) {
                case SYS_ptrace:
                    // Rewrite request -> 0 (PT_TRACE_ME) so PT_DENY_ATTACH
                    // is neutralised without changing the syscall number.
                    args[1] = ptr(0);
                    break;
                case SYS_sysctl: {
                    const mib = args[1];
                    const miblen = args[2].toInt32();
                    if (miblen >= 2 && !mib.isNull()) {
                        try {
                            if (mib.readU32() === CTL_KERN && mib.add(4).readU32() === KERN_PROC) {
                                this.savedOldp = args[3];
                            }
                        } catch {
                            // ignore
                        }
                    }
                    break;
                }
                case SYS_connect:
                    rewriteSockaddrPort(args[2]);
                    break;
                case SYS_stat:
                case SYS_lstat:
                case SYS_stat64:
                    rewriteFridaPath(args[1]);
                    break;
            }
        },
        onLeave(retval) {
            if (this.nr === SYS_sysctl && this.savedOldp && retval.toInt32() === 0) {
                const oldp = this.savedOldp as NativePointer;
                if (!oldp.isNull()) {
                    try {
                        const flags = oldp.add(32).readU32();
                        oldp.add(32).writeU32(flags & ~P_TRACED);
                    } catch {
                        // ignore
                    }
                }
            }
        },
    });
}

// ---------------------------------------------------------------------------
// (C2) Backstop hooks on libsystem_kernel thunks
// ---------------------------------------------------------------------------

const sysctlKernelPtr = kernelExport("__sysctl");
if (sysctlKernelPtr) {
    Interceptor.attach(sysctlKernelPtr, {
        onEnter(args) {
            // __sysctl(mib, miblen, oldp, oldlenp, newp, newlen)
            const mib = args[0];
            const miblen = args[1].toInt32();
            if (miblen >= 2 && !mib.isNull()) {
                try {
                    if (mib.readU32() === CTL_KERN && mib.add(4).readU32() === KERN_PROC) {
                        this.savedOldp = args[2];
                    }
                } catch {
                    // ignore
                }
            }
        },
        onLeave(retval) {
            if (this.savedOldp && retval.toInt32() === 0) {
                const oldp = this.savedOldp as NativePointer;
                if (!oldp.isNull()) {
                    try {
                        const flags = oldp.add(32).readU32();
                        oldp.add(32).writeU32(flags & ~P_TRACED);
                    } catch {
                        // ignore
                    }
                }
            }
        },
    });
}

const connectKernelPtr = kernelExport("__connect");
if (connectKernelPtr) {
    Interceptor.attach(connectKernelPtr, {
        onEnter(args) {
            rewriteSockaddrPort(args[1]);
        },
    });
}

for (const name of ["__stat", "__stat64", "__lstat"]) {
    const p = kernelExport(name);
    if (!p) continue;
    Interceptor.attach(p, {
        onEnter(args) {
            rewriteFridaPath(args[0]);
        },
    });
}

// ---------------------------------------------------------------------------
// (C3) task_info — sanitise TASK_DYLD_INFO output for app-side callers
// ---------------------------------------------------------------------------
// fd_check_dylibs reads dyld_all_image_infos.infoArray directly. We allocate
// a sanitised clone of the struct + array with frida-related imageFilePath
// pointers redirected to "/usr/lib/dyld", and patch the output pointer to
// point at our clone. Original OS structures are untouched.

const DYLD_IMAGE_INFO_SIZE = 24; // imageLoadAddress + imageFilePath + imageFileModDate

function sanitiseDyldInfo(infoOut: NativePointer): void {
    try {
        const aiiAddrU = infoOut.readU64();
        const aiiSizeU = infoOut.add(8).readU64();
        const aiiAddr = ptr(aiiAddrU.toString());
        const aiiSize = aiiSizeU.toNumber();
        if (aiiAddr.isNull() || aiiSize < 16) return;

        const fakeAii = Memory.alloc(aiiSize);
        Memory.copy(fakeAii, aiiAddr, aiiSize);

        const cnt = fakeAii.add(4).readU32();
        const arr = fakeAii.add(8).readPointer();
        if (cnt === 0 || arr.isNull()) return;

        const newArr = Memory.alloc(cnt * DYLD_IMAGE_INFO_SIZE);
        Memory.copy(newArr, arr, cnt * DYLD_IMAGE_INFO_SIZE);

        for (let i = 0; i < cnt; i++) {
            const slot = newArr.add(i * DYLD_IMAGE_INFO_SIZE);
            try {
                const pathPtr = slot.add(8).readPointer();
                if (pathPtr.isNull()) continue;
                const path = pathPtr.readCString();
                if (path && containsAny(path, FRIDA_DYLIB_NEEDLES)) {
                    slot.add(8).writePointer(Memory.allocUtf8String("/usr/lib/dyld"));
                }
            } catch {
                // ignore unreadable slot
            }
        }

        fakeAii.add(8).writePointer(newArr);
        infoOut.writeU64(uint64(fakeAii.toString()));
    } catch {
        // ignore
    }
}

const taskInfoPtr = kernelExport("task_info");
if (taskInfoPtr) {
    Interceptor.attach(taskInfoPtr, {
        onEnter(args) {
            this.flavor = args[1].toInt32();
            this.infoOut = args[2];
            this.fromAppCall = fromApp(this.returnAddress);
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;
            if (this.flavor !== TASK_DYLD_INFO) return;
            if (!this.fromAppCall) return;
            sanitiseDyldInfo(this.infoOut as NativePointer);
        },
    });
}

// ---------------------------------------------------------------------------
// (C4) thread_info — blank pth_name for THREAD_EXTENDED_INFO (app callers)
// ---------------------------------------------------------------------------
// thread_extended_info layout: pth_name[64] starts at offset 48.
const PTH_NAME_OFFSET = 48;

const threadInfoPtr = kernelExport("thread_info");
if (threadInfoPtr) {
    Interceptor.attach(threadInfoPtr, {
        onEnter(args) {
            this.flavor = args[1].toInt32();
            this.infoOut = args[2];
            this.fromAppCall = fromApp(this.returnAddress);
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;
            if (this.flavor !== THREAD_EXTENDED_INFO) return;
            if (!this.fromAppCall) return;
            const out = this.infoOut as NativePointer;
            if (!out || out.isNull()) return;
            try {
                const name = out.add(PTH_NAME_OFFSET).readCString();
                if (name && FRIDA_THREAD_NAMES.some((t) => name.startsWith(t))) {
                    out.add(PTH_NAME_OFFSET).writeU8(0);
                }
            } catch {
                // ignore
            }
        },
    });
}

// ---------------------------------------------------------------------------
// (C5) vm_region_recurse_64 — flip VM_PROT_WRITE bit for app callers
// ---------------------------------------------------------------------------
// fd_check_mem_signatures only scans regions where
//   (prot & VM_PROT_READ) && !(prot & VM_PROT_WRITE).
// vm_region_submap_info_64 lays out `protection` at offset 0. ORing
// VM_PROT_WRITE in makes the filter exclude every region.

const vmRegionRecursePtr = kernelExport("vm_region_recurse_64");
if (vmRegionRecursePtr) {
    Interceptor.attach(vmRegionRecursePtr, {
        onEnter(args) {
            this.info = args[4];
            this.fromAppCall = fromApp(this.returnAddress);
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;
            if (!this.fromAppCall) return;
            const info = this.info as NativePointer;
            if (!info || info.isNull()) return;
            try {
                const prot = info.readU32();
                info.writeU32(prot | VM_PROT_WRITE);
            } catch {
                // ignore
            }
        },
    });
}

// ---------------------------------------------------------------------------
// Boot: mutate state, install GOT redirect, RET-patch detector entry points.
// ---------------------------------------------------------------------------

scrubEnviron();
installExceptionPortsRedirect();
neutraliseDetectorEntry("fd_full_checks");
neutraliseDetectorEntry("fd_early_checks");
