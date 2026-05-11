📦
4809 /bypass.js
3554 /bypass.js.map
✄
// bypass.ts
var libKernel = Process.findModuleByName("libsystem_kernel.dylib");
var libC = Process.findModuleByName("libsystem_c.dylib");
function findSym(name) {
  for (const mod of [libKernel, libC]) {
    if (!mod)
      continue;
    const addr = mod.findExportByName(name);
    if (addr)
      return addr;
  }
  try {
    for (const mod of Process.enumerateModules()) {
      const addr = mod.findExportByName(name);
      if (addr)
        return addr;
    }
  } catch {
  }
  return null;
}
var PT_DENY_ATTACH = 31;
var ptracePtr = findSym("ptrace");
if (ptracePtr) {
  Interceptor.attach(ptracePtr, {
    onEnter(args) {
      if (args[0].toInt32() === PT_DENY_ATTACH) {
        args[0] = ptr(0);
      }
    }
  });
}
var P_TRACED = 2048;
var CTL_KERN = 1;
var KERN_PROC = 14;
var sysctlPtr = findSym("sysctl");
if (sysctlPtr) {
  let savedOldp = null;
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
        const flagOffset = 32;
        const flags = savedOldp.add(flagOffset).readU32();
        savedOldp.add(flagOffset).writeU32(flags & ~P_TRACED);
      }
      savedOldp = null;
    }
  });
}
var fridaPaths = ["/usr/lib/frida", "/usr/share/frida", "/usr/bin/frida", "/tmp/frida-"];
function isFridaPath(pathPtr) {
  try {
    const p = pathPtr.readCString() ?? "";
    return fridaPaths.some((prefix) => p.startsWith(prefix));
  } catch {
    return false;
  }
}
var accessPtr = findSym("access");
if (accessPtr) {
  Interceptor.attach(accessPtr, {
    onEnter(args) {
      if (isFridaPath(args[0])) {
        args[0] = Memory.allocUtf8String("/nonexistent_frida_probe");
      }
    }
  });
}
var openPtr = findSym("open");
if (openPtr) {
  Interceptor.attach(openPtr, {
    onEnter(args) {
      if (isFridaPath(args[0])) {
        args[0] = Memory.allocUtf8String("/nonexistent_frida_probe");
      }
    }
  });
}
var statPtr = findSym("stat") ?? findSym("stat$INODE64");
if (statPtr) {
  Interceptor.attach(statPtr, {
    onEnter(args) {
      if (isFridaPath(args[0])) {
        args[0] = Memory.allocUtf8String("/nonexistent_frida_probe");
      }
    }
  });
}
var lstatPtr = findSym("lstat") ?? findSym("lstat$INODE64");
if (lstatPtr) {
  Interceptor.attach(lstatPtr, {
    onEnter(args) {
      if (isFridaPath(args[0])) {
        args[0] = Memory.allocUtf8String("/nonexistent_frida_probe");
      }
    }
  });
}
var getenvPtr = findSym("getenv");
if (getenvPtr) {
  Interceptor.attach(getenvPtr, {
    onEnter(args) {
      try {
        const key = args[0].readCString() ?? "";
        if (key === "DYLD_INSERT_LIBRARIES") {
          args[0] = Memory.allocUtf8String("__bypass_no_such_env__");
        }
      } catch {
      }
    }
  });
}
var taskGetExcPortsPtr = findSym("task_get_exception_ports");
if (taskGetExcPortsPtr) {
  Interceptor.attach(taskGetExcPortsPtr, {
    onEnter(args) {
      this.cntPtr = args[3];
    },
    onLeave(_retval) {
      if (this.cntPtr && !this.cntPtr.isNull()) {
        this.cntPtr.writeU32(0);
      }
    }
  });
}
var FRIDA_PORT = 27042;
var connectPtr = findSym("connect");
if (connectPtr) {
  Interceptor.attach(connectPtr, {
    onEnter(args) {
      try {
        const addr = args[1];
        const family = addr.add(1).readU8();
        if (family === 2) {
          const port = addr.add(2).readU8() << 8 | addr.add(3).readU8();
          if (port === FRIDA_PORT) {
            addr.add(2).writeU8(0);
            addr.add(3).writeU8(1);
          }
        }
      } catch {
      }
    }
  });
}
var dyldGetImageNamePtr = findSym("_dyld_get_image_name");
if (dyldGetImageNamePtr) {
  Interceptor.attach(dyldGetImageNamePtr, {
    onLeave(retval) {
      try {
        if (retval.isNull())
          return;
        const name = retval.readCString() ?? "";
        if (name.toLowerCase().includes("frida")) {
          retval.replace(Memory.allocUtf8String("/usr/lib/system/libsystem_c.dylib"));
        }
      } catch {
      }
    }
  });
}
var fridaThreadNames = ["gum-js-loop", "gmain", "pool-frida"];
var pthreadGetNamePtr = findSym("pthread_getname_np");
if (pthreadGetNamePtr) {
  Interceptor.attach(pthreadGetNamePtr, {
    onEnter(args) {
      this.bufPtr = args[1];
    },
    onLeave(retval) {
      if (retval.toInt32() !== 0)
        return;
      if (!this.bufPtr || this.bufPtr.isNull())
        return;
      try {
        const name = this.bufPtr.readCString() ?? "";
        if (fridaThreadNames.some((t) => name.startsWith(t))) {
          this.bufPtr.writeU8(0);
        }
      } catch {
      }
    }
  });
}

✄
{
  "version": 3,
  "sources": ["bypass.ts"],
  "mappings": "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",
  "names": []
}
