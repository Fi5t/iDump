'use strict';
import ObjC from "frida-objc-bridge";

const O_RDONLY = 0;
const O_RDWR   = 2;
const O_CREAT  = 512;

const SEEK_SET = 0;
const SEEK_END = 2;

function allocStr(str: string): NativePointer {
    return Memory.allocUtf8String(str);
}

function getU32(addr: NativePointer | number): number {
    if (typeof addr == "number") addr = ptr(addr);
    return addr.readU32();
}

function putU64(addr: NativePointer | number, n: number): void {
    if (typeof addr == "number") addr = ptr(addr);
    addr.writeU64(n);
}

function malloc(size: number): NativePointer {
    return Memory.alloc(size);
}

function getNativeFunction(name: string, ret: string, args: string[]): NativeFunction<any, any> {
    const nptr = Module.getGlobalExportByName(name);
    if (nptr === null) {
        console.error("[agent] cannot find " + name);
        throw new Error("cannot find " + name);
    }
    const fn = new NativeFunction(nptr, ret as any, args as any);
    if (typeof fn === "undefined") {
        console.error("[agent] parse error " + name);
        throw new Error("parse error " + name);
    }
    return fn;
}


const NSSearchPathForDirectoriesInDomains = getNativeFunction("NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
const wrapper_open = getNativeFunction("open",   "int",     ["pointer", "int", "int"]);
const read         = getNativeFunction("read",   "int",     ["int", "pointer", "int"]);
const write        = getNativeFunction("write",  "int",     ["int", "pointer", "int"]);
const lseek        = getNativeFunction("lseek",  "int64",   ["int", "int64", "int"]);
const close        = getNativeFunction("close",  "int",     ["int"]);
const remove       = getNativeFunction("remove", "int",     ["pointer"]);
const access       = getNativeFunction("access", "int",     ["pointer", "int"]);
const dlopen       = getNativeFunction("dlopen", "pointer", ["pointer", "int"]);

const NS_DOCUMENT_DIRECTORY = 9;
const NS_USER_DOMAIN_MASK   = 1;

function getDocumentDir(): string {
    const npdirs = NSSearchPathForDirectoriesInDomains(NS_DOCUMENT_DIRECTORY, NS_USER_DOMAIN_MASK, 1);
    return new ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function open(pathname: string | NativePointer, flags: number, mode: number): number {
    if (typeof pathname == "string") pathname = allocStr(pathname);
    return wrapper_open(pathname, flags, mode) as number;
}

let modules: Module[] = [];
function getAllAppModules(): Module[] {
    modules = [];
    const tmpmods = Process.enumerateModules();
    for (let i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.indexOf(".app") != -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}

const FAT_MAGIC   = 0xcafebabe;
const FAT_CIGAM   = 0xbebafeca;
const MH_MAGIC    = 0xfeedface;
const MH_CIGAM    = 0xcefaedfe;
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const LC_ENCRYPTION_INFO    = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2C;


function swap32(value: number): number {
    return ((value & 0xff)       << 24) |
           ((value & 0xff00)     <<  8) |
           ((value & 0xff0000)   >>  8) |
           ((value >>> 24)       & 0xff);
}

// 32 MB per message — well under GLib/DBus's 128 MB hard cap.
const CHUNK_SIZE = 32 * 1024 * 1024;
const chunkBuf   = Memory.alloc(CHUNK_SIZE);

interface ModuleFiles {
    fmodule: number;
    foldmodule: number;
    newmodpath: string;
    modbase: NativePointer;
    headerSize: number;
}

function openModuleFiles(mod: Module, docDir: string): ModuleFiles | null {
    const newmodpath = docDir + "/" + mod.name + ".fid";
    const oldmodpath = mod.path;

    const nsNewPath = allocStr(newmodpath);
    if (!access(nsNewPath, 0)) {
        remove(nsNewPath);
    }

    const fmodule    = open(newmodpath, O_CREAT | O_RDWR, 0);
    const foldmodule = open(oldmodpath, O_RDONLY, 0);

    if (fmodule == -1 || foldmodule == -1) {
        console.error("[agent] Cannot open file " + newmodpath);
        return null;
    }

    const modbase  = mod.base;
    const magic    = getU32(modbase);
    let headerSize = 0;
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        headerSize = 28;
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        headerSize = 32;
    }

    return { fmodule, foldmodule, newmodpath, modbase, headerSize };
}

function copyBinary(fmodule: number, foldmodule: number, modbase: NativePointer): void {
    const buf = chunkBuf;
    const BUFSIZE = 4096;

    read(foldmodule, buf, BUFSIZE);

    const curCpuType    = getU32(modbase.add(4));
    const curCpuSubtype = getU32(modbase.add(8));

    let fileoffset = 0;
    let filesize   = 0;
    const magic    = getU32(buf);

    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        let archOff = 4;
        const archs = swap32(getU32(buf.add(archOff)));
        let cputype = 0;
        let cpusubtype = 0;
        for (let i = 0; i < archs; i++) {
            cputype    = swap32(getU32(buf.add(archOff + 4)));
            cpusubtype = swap32(getU32(buf.add(archOff + 8)));
            if (curCpuType == cputype && curCpuSubtype == cpusubtype) {
                fileoffset = swap32(getU32(buf.add(archOff + 12)));
                filesize   = swap32(getU32(buf.add(archOff + 16)));
                break;
            }
            archOff += 20;
        }

        if (fileoffset == 0 || filesize == 0) return;

        lseek(fmodule,    0,          SEEK_SET);
        lseek(foldmodule, fileoffset, SEEK_SET);
        for (let i = 0; i < Math.floor(filesize / BUFSIZE); i++) {
            read(foldmodule,  buf, BUFSIZE);
            write(fmodule, buf, BUFSIZE);
        }
        if (filesize % BUFSIZE) {
            read(foldmodule,  buf, filesize % BUFSIZE);
            write(fmodule, buf, filesize % BUFSIZE);
        }
    } else {
        lseek(foldmodule, 0, SEEK_SET);
        lseek(fmodule,    0, SEEK_SET);
        let readLen: number;
        while ((readLen = read(foldmodule, buf, BUFSIZE) as number) > 0) {
            write(fmodule, buf, readLen);
        }
    }
}

function patchEncryptionInfo(fmodule: number, modbase: NativePointer, headerSize: number): void {
    const ncmds = getU32(modbase.add(16));
    let cmdOff  = headerSize;
    let cryptidOffset: number | null = null;
    let cryptOff  = 0;
    let cryptSize = 0;

    let cmd = 0;
    let cmdsize = 0;
    for (let i = 0; i < ncmds; i++) {
        cmd     = getU32(modbase.add(cmdOff));
        cmdsize = getU32(modbase.add(cmdOff + 4));
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            cryptidOffset = cmdOff + 16;
            cryptOff      = getU32(modbase.add(cmdOff + 8));
            cryptSize     = getU32(modbase.add(cmdOff + 12));
        }
        cmdOff += cmdsize;
    }

    if (cryptidOffset !== null) {
        const tpbuf = malloc(8);
        putU64(tpbuf, 0);
        lseek(fmodule, cryptidOffset, SEEK_SET);
        write(fmodule, tpbuf, 4);
        lseek(fmodule, cryptOff, SEEK_SET);
        write(fmodule, modbase.add(cryptOff), cryptSize);
    }
}

function dumpModule(name: string): string | undefined {
    if (modules.length === 0) modules = getAllAppModules();

    let targetmod: Module | null = null;
    for (let i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        console.error("[agent] Cannot find module: " + name);
        return;
    }

    const files = openModuleFiles(targetmod, getDocumentDir());
    if (files == null) return;

    const { fmodule, foldmodule, newmodpath, modbase, headerSize } = files;

    copyBinary(fmodule, foldmodule, modbase);
    patchEncryptionInfo(fmodule, modbase, headerSize);

    close(fmodule);
    close(foldmodule);
    return newmodpath;
}

function loadAllDynamicLibrary(app_path: ObjC.Object): void {
    const defaultManager = ObjC.classes.NSFileManager.defaultManager();
    const errorPtr = Memory.alloc(Process.pointerSize);
    errorPtr.writePointer(NULL);
    const filenames = defaultManager.contentsOfDirectoryAtPath_error_(app_path, errorPtr);
    for (let i = 0, l = filenames.count(); i < l; i++) {
        const file_name = filenames.objectAtIndex_(i);
        const file_path = app_path.stringByAppendingPathComponent_(file_name);
        if (file_name.hasSuffix_(".bundle") ||
                file_name.hasSuffix_(".momd") ||
                file_name.hasSuffix_(".strings") ||
                file_name.hasSuffix_(".appex") ||
                file_name.hasSuffix_(".app") ||
                file_name.hasSuffix_(".lproj") ||
                file_name.hasSuffix_(".storyboardc")) {
            continue;
        }
        if (file_name.hasSuffix_(".framework")) {
            const bundle = ObjC.classes.NSBundle.bundleWithPath_(file_path);
            if (!bundle.isLoaded()) {
                bundle.load();
            }
        } else {
            const isDirPtr = Memory.alloc(Process.pointerSize);
            isDirPtr.writePointer(NULL);
            defaultManager.fileExistsAtPath_isDirectory_(file_path, isDirPtr);
            if (isDirPtr.readU8() !== 0) {
                loadAllDynamicLibrary(file_path);
            } else {
                if (file_name.hasSuffix_(".dylib")) {
                    let is_loaded = 0;
                    for (let j = 0; j < modules.length; j++) {
                        if (modules[j].path.indexOf(file_name) != -1) {
                            is_loaded = 1;
                            break;
                        }
                    }
                    if (!is_loaded) {
                        dlopen(allocStr(file_path.UTF8String()), 9);
                    }
                }
            }
        }
    }
}

function sendFileChunked(payload: object, filePath: string): void {
    const fd = open(filePath, O_RDONLY, 0);
    if (fd === -1) return;

    const totalSize = parseInt(lseek(fd, 0, SEEK_END).toString());
    lseek(fd, 0, SEEK_SET);

    const numChunks = Math.max(1, Math.ceil(totalSize / CHUNK_SIZE));

    for (let i = 0; i < numChunks; i++) {
        const toRead = Math.min(CHUNK_SIZE, totalSize - i * CHUNK_SIZE);
        let bytesRead = 0;
        while (bytesRead < toRead) {
            const n = read(fd, chunkBuf.add(bytesRead), toRead - bytesRead) as number;
            if (n <= 0) break;
            bytesRead += n;
        }
        send(
            Object.assign({}, payload, { size: totalSize, chunk: i, chunks: numChunks }),
            chunkBuf.readByteArray(bytesRead)
        );
    }
    close(fd);
}

function sendAppBundleViaFrida(appPath: string): void {
    const appBaseName = appPath.split("/").pop();
    const fm          = ObjC.classes.NSFileManager.defaultManager();
    const nsAppPath   = ObjC.classes.NSString.stringWithString_(appPath);

    const errorPtr = Memory.alloc(Process.pointerSize);
    errorPtr.writePointer(NULL);
    const subpaths = fm.subpathsOfDirectoryAtPath_error_(nsAppPath, errorPtr);

    if (subpaths == null) {
        console.error("[agent] failed to list app bundle: " + appPath);
        return;
    }

    // NSFileManager.subpathsOfDirectoryAtPath follows symlinks, so the same
    // underlying file can appear at multiple paths (e.g. Foo, Versions/A/Foo,
    // Versions/Current/Foo). Track resolved paths to send each file only once.
    const sentRealPaths = new Set<string>();
    const count         = parseInt(subpaths.count().toString());
    const isDirPtr      = Memory.alloc(Process.pointerSize);

    for (let i = 0; i < count; i++) {
        const relPath    = subpaths.objectAtIndex_(i).toString();
        const fullPath   = appPath + "/" + relPath;
        const nsFullPath = ObjC.classes.NSString.stringWithString_(fullPath);

        isDirPtr.writePointer(NULL);
        fm.fileExistsAtPath_isDirectory_(nsFullPath, isDirPtr);
        if (isDirPtr.readU8() !== 0) continue;

        const realPath = nsFullPath.stringByResolvingSymlinksInPath().toString();
        if (sentRealPaths.has(realPath)) continue;
        sentRealPaths.add(realPath);

        sendFileChunked({ app_file: relPath, app: appBaseName }, fullPath);
    }
}

function handleMessage(message: { mode?: string }): void {
    const isUsb = (typeof message === "object" && message !== null && message.mode === "usb");

    modules = getAllAppModules();
    const app_path = ObjC.classes.NSBundle.mainBundle().bundlePath();
    loadAllDynamicLibrary(app_path);
    modules = getAllAppModules();
    for (let i = 0; i < modules.length; i++) {
        const result = dumpModule(modules[i].path);
        if (!result) continue;

        if (isUsb) {
            const basename = result.split("/").pop();
            sendFileChunked({ dump: basename, path: modules[i].path }, result);
            remove(allocStr(result));
        } else {
            send({ dump: result, path: modules[i].path });
        }
    }

    if (isUsb) {
        sendAppBundleViaFrida(app_path.toString());
    } else {
        send({ app: app_path.toString() });
    }

    send({ done: "ok" });
    recv(handleMessage);
}

recv(handleMessage);
