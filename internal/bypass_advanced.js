📦
10953 /bypass_advanced.js
7808 /bypass_advanced.js.map
✄
// bypass_advanced.ts
var SYS_ptrace = 26;
var SYS_connect = 98;
var SYS_stat = 188;
var SYS_lstat = 190;
var SYS_sysctl = 202;
var SYS_stat64 = 338;
var CTL_KERN = 1;
var KERN_PROC = 14;
var P_TRACED = 2048;
var AF_INET = 2;
var AF_INET6 = 30;
var FRIDA_PORT = 27042;
var TASK_DYLD_INFO = 17;
var THREAD_EXTENDED_INFO = 5;
var VM_PROT_WRITE = 2;
var MACH_PORT_NULL = 0;
var DYLD_INSERT_KEY = "DYLD_INSERT_LIBRARIES";
var FRIDA_THREAD_NAMES = ["gum-js-loop", "gmain", "pool-frida"];
var FRIDA_PATH_NEEDLES = ["frida", "FridaGadget", "gadget", "cynict"];
var FRIDA_DYLIB_NEEDLES = ["frida", "FridaGadget", "frida-agent", "frida_agent"];
var ARM64_RET = 3596551104;
var libKernel = Process.findModuleByName("libsystem_kernel.dylib");
var libC = Process.findModuleByName("libsystem_c.dylib");
var libPthread = Process.findModuleByName("libsystem_pthread.dylib");
function findMainExecutable() {
  const MH_EXECUTE = 2;
  for (const m of Process.enumerateModules()) {
    try {
      if (m.base.add(12).readU32() === MH_EXECUTE)
        return m;
    } catch {
    }
  }
  return null;
}
var mainModule = findMainExecutable();
var mainBase = mainModule ? mainModule.base : ptr(0);
var mainEnd = mainModule ? mainModule.base.add(mainModule.size) : ptr(0);
function fromApp(retAddr) {
  if (!retAddr || !mainModule)
    return false;
  return retAddr.compare(mainBase) >= 0 && retAddr.compare(mainEnd) < 0;
}
function kernelExport(name) {
  return libKernel ? libKernel.findExportByName(name) : null;
}
function libcExport(name) {
  return libC ? libC.findExportByName(name) : null;
}
function findSym(name) {
  for (const mod of [libKernel, libC, libPthread]) {
    if (!mod)
      continue;
    const p = mod.findExportByName(name);
    if (p)
      return p;
  }
  try {
    for (const mod of Process.enumerateModules()) {
      const p = mod.findExportByName(name);
      if (p)
        return p;
    }
  } catch {
  }
  return null;
}
function containsAny(haystack, needles) {
  const lower = haystack.toLowerCase();
  return needles.some((n) => lower.indexOf(n.toLowerCase()) >= 0);
}
function findInMainModule(name) {
  if (!mainModule)
    return null;
  const exp = mainModule.findExportByName(name);
  if (exp)
    return exp;
  try {
    for (const s of mainModule.enumerateSymbols()) {
      if (s.name === name || s.name === "_" + name)
        return s.address;
    }
  } catch {
  }
  try {
    const ds = DebugSymbol.fromName(name);
    if (ds && !ds.address.isNull())
      return ds.address;
  } catch {
  }
  return null;
}
function neutraliseDetectorEntry(name) {
  const p = findInMainModule(name);
  if (!p)
    return false;
  try {
    Memory.patchCode(p, 4, (code) => code.writeU32(ARM64_RET));
    return true;
  } catch {
    return false;
  }
}
function scrubEnviron() {
  const nsEnvironPtr = libcExport("_NSGetEnviron");
  if (!nsEnvironPtr)
    return false;
  const fn = new NativeFunction(nsEnvironPtr, "pointer", []);
  const envPtrPtr = fn();
  if (envPtrPtr.isNull())
    return false;
  let environ = envPtrPtr.readPointer();
  if (environ.isNull())
    return false;
  const keyLen = DYLD_INSERT_KEY.length;
  let scrubbed = false;
  while (true) {
    const entry = environ.readPointer();
    if (entry.isNull())
      break;
    try {
      const head = entry.readCString(keyLen + 1) ?? "";
      if (head.length >= keyLen + 1 && head.startsWith(DYLD_INSERT_KEY) && head.charAt(keyLen) === "=") {
        entry.add(1).writeU8(95);
        scrubbed = true;
      }
    } catch {
    }
    environ = environ.add(Process.pointerSize);
  }
  return scrubbed;
}
function installExceptionPortsRedirect() {
  if (!mainModule)
    return 0;
  const stub = new NativeCallback((_task, _exceptionMask, masks, masksCntPtr, handlers, behaviors, flavors) => {
    try {
      if (!masksCntPtr.isNull())
        masksCntPtr.writeU32(1);
      if (!masks.isNull())
        masks.writeU32(0);
      if (!handlers.isNull())
        handlers.writeU32(MACH_PORT_NULL);
      if (!behaviors.isNull())
        behaviors.writeU32(0);
      if (!flavors.isNull())
        flavors.writeU32(0);
    } catch {
    }
    return 0;
  }, "int", ["uint", "int", "pointer", "pointer", "pointer", "pointer", "pointer"]);
  let patched = 0;
  try {
    for (const imp of mainModule.enumerateImports()) {
      if (imp.name !== "task_get_exception_ports")
        continue;
      const slot = imp.slot;
      if (!slot || slot.isNull())
        continue;
      try {
        const pageSize = Process.pageSize;
        const offsetInPage = slot.toInt32() & pageSize - 1;
        const pageBase = slot.sub(offsetInPage);
        Memory.protect(pageBase, pageSize, "rw-");
        slot.writePointer(stub);
        Memory.protect(pageBase, pageSize, "r--");
        patched++;
      } catch {
      }
    }
  } catch {
  }
  return patched;
}
function rewriteSockaddrPort(addr) {
  if (addr.isNull())
    return;
  try {
    const family = addr.add(1).readU8();
    if (family === AF_INET || family === AF_INET6) {
      const port = addr.add(2).readU8() << 8 | addr.add(3).readU8();
      if (port === FRIDA_PORT) {
        addr.add(2).writeU8(0);
        addr.add(3).writeU8(1);
      }
    }
  } catch {
  }
}
function rewriteFridaPath(arg) {
  try {
    const p = arg.readCString();
    if (p && containsAny(p, FRIDA_PATH_NEEDLES)) {
      arg.writePointer(Memory.allocUtf8String("/nonexistent_frida_probe"));
    }
  } catch {
  }
}
var syscallPtr = findSym("syscall");
if (syscallPtr) {
  Interceptor.attach(syscallPtr, {
    onEnter(args) {
      const nr = args[0].toInt32();
      this.nr = nr;
      switch (nr) {
        case SYS_ptrace:
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
        const oldp = this.savedOldp;
        if (!oldp.isNull()) {
          try {
            const flags = oldp.add(32).readU32();
            oldp.add(32).writeU32(flags & ~P_TRACED);
          } catch {
          }
        }
      }
    }
  });
}
var sysctlKernelPtr = kernelExport("__sysctl");
if (sysctlKernelPtr) {
  Interceptor.attach(sysctlKernelPtr, {
    onEnter(args) {
      const mib = args[0];
      const miblen = args[1].toInt32();
      if (miblen >= 2 && !mib.isNull()) {
        try {
          if (mib.readU32() === CTL_KERN && mib.add(4).readU32() === KERN_PROC) {
            this.savedOldp = args[2];
          }
        } catch {
        }
      }
    },
    onLeave(retval) {
      if (this.savedOldp && retval.toInt32() === 0) {
        const oldp = this.savedOldp;
        if (!oldp.isNull()) {
          try {
            const flags = oldp.add(32).readU32();
            oldp.add(32).writeU32(flags & ~P_TRACED);
          } catch {
          }
        }
      }
    }
  });
}
var connectKernelPtr = kernelExport("__connect");
if (connectKernelPtr) {
  Interceptor.attach(connectKernelPtr, {
    onEnter(args) {
      rewriteSockaddrPort(args[1]);
    }
  });
}
for (const name of ["__stat", "__stat64", "__lstat"]) {
  const p = kernelExport(name);
  if (!p)
    continue;
  Interceptor.attach(p, {
    onEnter(args) {
      rewriteFridaPath(args[0]);
    }
  });
}
var DYLD_IMAGE_INFO_SIZE = 24;
function sanitiseDyldInfo(infoOut) {
  try {
    const aiiAddrU = infoOut.readU64();
    const aiiSizeU = infoOut.add(8).readU64();
    const aiiAddr = ptr(aiiAddrU.toString());
    const aiiSize = aiiSizeU.toNumber();
    if (aiiAddr.isNull() || aiiSize < 16)
      return;
    const fakeAii = Memory.alloc(aiiSize);
    Memory.copy(fakeAii, aiiAddr, aiiSize);
    const cnt = fakeAii.add(4).readU32();
    const arr = fakeAii.add(8).readPointer();
    if (cnt === 0 || arr.isNull())
      return;
    const newArr = Memory.alloc(cnt * DYLD_IMAGE_INFO_SIZE);
    Memory.copy(newArr, arr, cnt * DYLD_IMAGE_INFO_SIZE);
    for (let i = 0; i < cnt; i++) {
      const slot = newArr.add(i * DYLD_IMAGE_INFO_SIZE);
      try {
        const pathPtr = slot.add(8).readPointer();
        if (pathPtr.isNull())
          continue;
        const path = pathPtr.readCString();
        if (path && containsAny(path, FRIDA_DYLIB_NEEDLES)) {
          slot.add(8).writePointer(Memory.allocUtf8String("/usr/lib/dyld"));
        }
      } catch {
      }
    }
    fakeAii.add(8).writePointer(newArr);
    infoOut.writeU64(uint64(fakeAii.toString()));
  } catch {
  }
}
var taskInfoPtr = kernelExport("task_info");
if (taskInfoPtr) {
  Interceptor.attach(taskInfoPtr, {
    onEnter(args) {
      this.flavor = args[1].toInt32();
      this.infoOut = args[2];
      this.fromAppCall = fromApp(this.returnAddress);
    },
    onLeave(retval) {
      if (retval.toInt32() !== 0)
        return;
      if (this.flavor !== TASK_DYLD_INFO)
        return;
      if (!this.fromAppCall)
        return;
      sanitiseDyldInfo(this.infoOut);
    }
  });
}
var PTH_NAME_OFFSET = 48;
var threadInfoPtr = kernelExport("thread_info");
if (threadInfoPtr) {
  Interceptor.attach(threadInfoPtr, {
    onEnter(args) {
      this.flavor = args[1].toInt32();
      this.infoOut = args[2];
      this.fromAppCall = fromApp(this.returnAddress);
    },
    onLeave(retval) {
      if (retval.toInt32() !== 0)
        return;
      if (this.flavor !== THREAD_EXTENDED_INFO)
        return;
      if (!this.fromAppCall)
        return;
      const out = this.infoOut;
      if (!out || out.isNull())
        return;
      try {
        const name = out.add(PTH_NAME_OFFSET).readCString();
        if (name && FRIDA_THREAD_NAMES.some((t) => name.startsWith(t))) {
          out.add(PTH_NAME_OFFSET).writeU8(0);
        }
      } catch {
      }
    }
  });
}
var vmRegionRecursePtr = kernelExport("vm_region_recurse_64");
if (vmRegionRecursePtr) {
  Interceptor.attach(vmRegionRecursePtr, {
    onEnter(args) {
      this.info = args[4];
      this.fromAppCall = fromApp(this.returnAddress);
    },
    onLeave(retval) {
      if (retval.toInt32() !== 0)
        return;
      if (!this.fromAppCall)
        return;
      const info = this.info;
      if (!info || info.isNull())
        return;
      try {
        const prot = info.readU32();
        info.writeU32(prot | VM_PROT_WRITE);
      } catch {
      }
    }
  });
}
scrubEnviron();
installExceptionPortsRedirect();
neutraliseDetectorEntry("fd_full_checks");
neutraliseDetectorEntry("fd_early_checks");

✄
{
  "version": 3,
  "sources": ["bypass_advanced.ts"],
  "mappings": "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",
  "names": []
}
