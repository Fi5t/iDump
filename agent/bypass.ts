// Built-in anti-Frida bypass agent.
// Injected while the target process is suspended (spawn-gating).
// Hooks must use only native C APIs — ObjC runtime is not yet initialised.

// iOS system calls live in libsystem_kernel.dylib; everything else is in libc.
const libKernel = Process.findModuleByName("libsystem_kernel.dylib");
const libC = Process.findModuleByName("libsystem_c.dylib");

function findSym(name: string): NativePointer | null {
    for (const mod of [libKernel, libC]) {
        if (!mod) continue;
        const addr = mod.findExportByName(name);
        if (addr) return addr;
    }
    try {
        for (const mod of Process.enumerateModules()) {
            const addr = mod.findExportByName(name);
            if (addr) return addr;
        }
    } catch {
        // ignore
    }
    return null;
}

const PT_DENY_ATTACH = 31;

// ptrace(PT_DENY_ATTACH, ...) — most common iOS anti-debug technique.
// Rewrite the request to PT_TRACE_ME (0) so the syscall becomes harmless.
const ptracePtr = findSym("ptrace");
if (ptracePtr) {
    Interceptor.attach(ptracePtr, {
        onEnter(args) {
            if (args[0].toInt32() === PT_DENY_ATTACH) {
                args[0] = ptr(0);
            }
        },
    });
}

// sysctl(KERN_PROC / KERN_PROC_PID) — checks kinfo_proc.p_flag for P_TRACED.
// Clear that flag in the output buffer so the app thinks it is not traced.
const P_TRACED = 0x00000800;
const CTL_KERN = 1;
const KERN_PROC = 14;

const sysctlPtr = findSym("sysctl");
if (sysctlPtr) {
    let savedOldp: NativePointer | null = null;

    Interceptor.attach(sysctlPtr, {
        onEnter(args) {
            const mib = args[0];
            if (mib.readU32() === CTL_KERN && mib.add(4).readU32() === KERN_PROC) {
                savedOldp = args[2];
            } else {
                savedOldp = null;
            }
        },
        onLeave(retval) {
            if (savedOldp && !savedOldp.isNull() && retval.toInt32() === 0) {
                // kinfo_proc.p_flag is at offset 32 in the struct (arm64 / x86_64).
                const flagOffset = 32;
                const flags = savedOldp.add(flagOffset).readU32();
                savedOldp.add(flagOffset).writeU32(flags & ~P_TRACED);
            }
            savedOldp = null;
        },
    });
}

// access() / open() / stat() — existence checks for Frida artefacts on the filesystem.
const fridaPaths = ["/usr/lib/frida", "/usr/share/frida", "/usr/bin/frida", "/tmp/frida-"];

function isFridaPath(pathPtr: NativePointer): boolean {
    try {
        const p = pathPtr.readCString() ?? "";
        return fridaPaths.some((prefix) => p.startsWith(prefix));
    } catch {
        return false;
    }
}

const accessPtr = findSym("access");
if (accessPtr) {
    Interceptor.attach(accessPtr, {
        onEnter(args) {
            if (isFridaPath(args[0])) {
                args[0] = Memory.allocUtf8String("/nonexistent_frida_probe");
            }
        },
    });
}

const openPtr = findSym("open");
if (openPtr) {
    Interceptor.attach(openPtr, {
        onEnter(args) {
            if (isFridaPath(args[0])) {
                args[0] = Memory.allocUtf8String("/nonexistent_frida_probe");
            }
        },
    });
}

// stat() / lstat() — fd_check_filesystem uses stat(), not access()/open().
// Try both "stat" and "stat$INODE64" (older iOS SDKs export the latter).
const statPtr = findSym("stat") ?? findSym("stat$INODE64");
if (statPtr) {
    Interceptor.attach(statPtr, {
        onEnter(args) {
            if (isFridaPath(args[0])) {
                args[0] = Memory.allocUtf8String("/nonexistent_frida_probe");
            }
        },
    });
}

const lstatPtr = findSym("lstat") ?? findSym("lstat$INODE64");
if (lstatPtr) {
    Interceptor.attach(lstatPtr, {
        onEnter(args) {
            if (isFridaPath(args[0])) {
                args[0] = Memory.allocUtf8String("/nonexistent_frida_probe");
            }
        },
    });
}

// getenv("DYLD_INSERT_LIBRARIES") — app checks for dylib injection environment variable.
// Redirect the key to a non-existent name so getenv returns NULL.
const getenvPtr = findSym("getenv");
if (getenvPtr) {
    Interceptor.attach(getenvPtr, {
        onEnter(args) {
            try {
                const key = args[0].readCString() ?? "";
                if (key === "DYLD_INSERT_LIBRARIES") {
                    args[0] = Memory.allocUtf8String("__bypass_no_such_env__");
                }
            } catch {
                // ignore
            }
        },
    });
}

// task_get_exception_ports — Frida server installs a Mach exception handler whose port is
// valid. Zero out the count output so the detection loop iterates zero times.
const taskGetExcPortsPtr = findSym("task_get_exception_ports");
if (taskGetExcPortsPtr) {
    Interceptor.attach(taskGetExcPortsPtr, {
        onEnter(args) {
            // args[3] = mach_msg_type_number_t *count (output parameter)
            this.cntPtr = args[3];
        },
        onLeave(_retval) {
            if (this.cntPtr && !this.cntPtr.isNull()) {
                this.cntPtr.writeU32(0);
            }
        },
    });
}

// connect() — app probes TCP 127.0.0.1:27042 (Frida server default port, XOR-obfuscated).
// Darwin sockaddr_in layout: sin_len(u8@0), sin_family(u8@1), sin_port(u16be@2), sin_addr(@4).
// Redirect port 27042 to port 1 (big-endian 0x0001) — virtually never listening on iOS.
const FRIDA_PORT = 27042;
const connectPtr = findSym("connect");
if (connectPtr) {
    Interceptor.attach(connectPtr, {
        onEnter(args) {
            try {
                const addr = args[1];
                const family = addr.add(1).readU8(); // sin_family at offset 1 on Darwin
                if (family === 2 /* AF_INET */) {
                    const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
                    if (port === FRIDA_PORT) {
                        addr.add(2).writeU8(0x00);
                        addr.add(3).writeU8(0x01);
                    }
                }
            } catch {
                // ignore
            }
        },
    });
}

// _dyld_get_image_name — Frida's agent dylib is already loaded at injection time.
// If the returned name contains "frida", replace it with an innocuous system library path.
const dyldGetImageNamePtr = findSym("_dyld_get_image_name");
if (dyldGetImageNamePtr) {
    Interceptor.attach(dyldGetImageNamePtr, {
        onLeave(retval) {
            try {
                if (retval.isNull()) return;
                const name = retval.readCString() ?? "";
                if (name.toLowerCase().includes("frida")) {
                    retval.replace(Memory.allocUtf8String("/usr/lib/system/libsystem_c.dylib"));
                }
            } catch {
                // ignore
            }
        },
    });
}

// pthread_getname_np — Frida runtime threads are named "gum-js-loop", "gmain", "pool-frida".
// On success (retval == 0) blank the name buffer so the detection check sees an empty string
// and skips that thread. Use per-invocation this.bufPtr to be thread-safe.
const fridaThreadNames = ["gum-js-loop", "gmain", "pool-frida"];
const pthreadGetNamePtr = findSym("pthread_getname_np");
if (pthreadGetNamePtr) {
    Interceptor.attach(pthreadGetNamePtr, {
        onEnter(args) {
            this.bufPtr = args[1]; // char *buf
        },
        onLeave(retval) {
            if (retval.toInt32() !== 0) return;
            if (!this.bufPtr || this.bufPtr.isNull()) return;
            try {
                const name = this.bufPtr.readCString() ?? "";
                if (fridaThreadNames.some((t) => name.startsWith(t))) {
                    this.bufPtr.writeU8(0);
                }
            } catch {
                // ignore
            }
        },
    });
}
