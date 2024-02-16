
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .jsvm import JSObject

class Instruction:

    @staticmethod
    def parse(target) -> 'JSObject':
        pass
        
class Module:

    @staticmethod
    def load(name) -> 'JSObject':
        pass
        

    @staticmethod
    def ensureInitialized(name) -> 'JSObject':
        pass
        

    @staticmethod
    def findBaseAddress(name) -> 'JSObject':
        pass
        

    @staticmethod
    def getBaseAddress(name) -> 'JSObject':
        pass
        

    @staticmethod
    def findExportByName(moduleName, exportName) -> 'JSObject':
        pass
        

    @staticmethod
    def getExportByName(moduleName, exportName) -> 'JSObject':
        pass
        
class ModuleMap:

    pass

class NativeCallback:

    pass

class DebugSymbol:

    @staticmethod
    def fromAddress(address) -> 'JSObject':
        pass
        

    @staticmethod
    def fromName(name) -> 'JSObject':
        pass
        

    @staticmethod
    def getFunctionByName(name) -> 'JSObject':
        pass
        

    @staticmethod
    def findFunctionsNamed(name) -> 'JSObject':
        pass
        

    @staticmethod
    def findFunctionsMatching(glob) -> 'JSObject':
        pass
        

    @staticmethod
    def load(path) -> 'JSObject':
        pass
        
class Instruction:

    @staticmethod
    def parse(target) -> 'JSObject':
        pass
        
class X86Writer:

    pass

class X86Relocator:

    pass

class ArmWriter:

    pass

class ArmRelocator:

    pass

class ThumbWriter:

    pass

class ThumbRelocator:

    pass

class Arm64Writer:

    pass

class Arm64Relocator:

    pass

class MipsWriter:

    pass

class MipsRelocator:

    pass

class Script:
    runtime = None


    @staticmethod
    def evaluate(name, source) -> 'JSObject':
        pass
        

    @staticmethod
    def load(name, source) -> 'JSObject':
        pass
        

    @staticmethod
    def registerSourceMap(name, json) -> 'JSObject':
        pass
        

    @staticmethod
    def nextTick(func, *args) -> 'JSObject':
        pass
        

    @staticmethod
    def pin() -> 'JSObject':
        pass
        

    @staticmethod
    def unpin() -> 'JSObject':
        pass
        

    @staticmethod
    def bindWeak(target, callback) -> 'JSObject':
        pass
        

    @staticmethod
    def unbindWeak(id) -> 'JSObject':
        pass
        

    @staticmethod
    def setGlobalAccessHandler(handler) -> 'JSObject':
        pass
        
class Frida:
    version = None

    heapSize = None

class Process:
    id = None

    arch = None

    platform = None

    pageSize = None

    pointerSize = None

    codeSigningPolicy = None

    mainModule = None


    @staticmethod
    def getCurrentDir() -> 'JSObject':
        pass
        

    @staticmethod
    def getHomeDir() -> 'JSObject':
        pass
        

    @staticmethod
    def getTmpDir() -> 'JSObject':
        pass
        

    @staticmethod
    def isDebuggerAttached() -> 'JSObject':
        pass
        

    @staticmethod
    def getCurrentThreadId() -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateThreads() -> 'JSObject':
        pass
        

    @staticmethod
    def findModuleByAddress(address) -> 'JSObject':
        pass
        

    @staticmethod
    def getModuleByAddress(address) -> 'JSObject':
        pass
        

    @staticmethod
    def findModuleByName(name) -> 'JSObject':
        pass
        

    @staticmethod
    def getModuleByName(name) -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateModules() -> 'JSObject':
        pass
        

    @staticmethod
    def findRangeByAddress(address) -> 'JSObject':
        pass
        

    @staticmethod
    def getRangeByAddress(address) -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateRanges(specifier) -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateMallocRanges() -> 'JSObject':
        pass
        

    @staticmethod
    def setExceptionHandler(callback) -> 'JSObject':
        pass
        
class Memory:

    @staticmethod
    def scan(address, size, pattern, callbacks) -> 'JSObject':
        pass
        

    @staticmethod
    def scanSync(address, size, pattern) -> 'JSObject':
        pass
        

    @staticmethod
    def alloc(size, options) -> 'JSObject':
        pass
        

    @staticmethod
    def allocUtf8String(str) -> 'JSObject':
        pass
        

    @staticmethod
    def allocUtf16String(str) -> 'JSObject':
        pass
        

    @staticmethod
    def allocAnsiString(str) -> 'JSObject':
        pass
        

    @staticmethod
    def copy(dst, src, n) -> 'JSObject':
        pass
        

    @staticmethod
    def dup(address, size) -> 'JSObject':
        pass
        

    @staticmethod
    def protect(address, size, protection) -> 'JSObject':
        pass
        

    @staticmethod
    def queryProtection(address) -> 'JSObject':
        pass
        

    @staticmethod
    def patchCode(address, size, apply) -> 'JSObject':
        pass
        
class MemoryAccessMonitor:

    @staticmethod
    def enable(ranges, callbacks) -> 'JSObject':
        pass
        

    @staticmethod
    def disable() -> 'JSObject':
        pass
        
class Thread:

    @staticmethod
    def backtrace(context, backtracer) -> 'JSObject':
        pass
        

    @staticmethod
    def sleep(delay) -> 'JSObject':
        pass
        
class Interceptor:

    @staticmethod
    def attach(target, callbacksOrProbe, data) -> 'JSObject':
        pass
        

    @staticmethod
    def detachAll() -> 'JSObject':
        pass
        

    @staticmethod
    def replace(target, replacement, data) -> 'JSObject':
        pass
        

    @staticmethod
    def replaceFast(target, replacement) -> 'JSObject':
        pass
        

    @staticmethod
    def revert(target) -> 'JSObject':
        pass
        

    @staticmethod
    def flush() -> 'JSObject':
        pass
        
class Stalker:

    @staticmethod
    def exclude(range) -> 'JSObject':
        pass
        

    @staticmethod
    def follow(threadId, options) -> 'JSObject':
        pass
        

    @staticmethod
    def unfollow(threadId) -> 'JSObject':
        pass
        

    @staticmethod
    def parse(events, options) -> 'JSObject':
        pass
        

    @staticmethod
    def flush() -> 'JSObject':
        pass
        

    @staticmethod
    def garbageCollect() -> 'JSObject':
        pass
        

    @staticmethod
    def invalidate(threadId, address) -> 'JSObject':
        pass
        

    @staticmethod
    def addCallProbe(address, callback, data) -> 'JSObject':
        pass
        

    @staticmethod
    def removeCallProbe(callbackId) -> 'JSObject':
        pass
        
class Kernel:
    available = None

    pageSize = None


    @staticmethod
    def enumerateModules() -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateRanges(specifier) -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateModuleRanges(name, protection) -> 'JSObject':
        pass
        

    @staticmethod
    def alloc(size) -> 'JSObject':
        pass
        

    @staticmethod
    def protect(address, size, protection) -> 'JSObject':
        pass
        

    @staticmethod
    def scan(address, size, pattern, callbacks) -> 'JSObject':
        pass
        

    @staticmethod
    def scanSync(address, size, pattern) -> 'JSObject':
        pass
        

    @staticmethod
    def readS8(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readU8(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readS16(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readU16(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readS32(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readU32(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readS64(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readU64(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readShort(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readUShort(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readInt(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readUInt(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readLong(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readULong(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readFloat(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readDouble(address) -> 'JSObject':
        pass
        

    @staticmethod
    def readByteArray(address, length) -> 'JSObject':
        pass
        

    @staticmethod
    def readCString(address, size) -> 'JSObject':
        pass
        

    @staticmethod
    def readUtf8String(address, size) -> 'JSObject':
        pass
        

    @staticmethod
    def readUtf16String(address, length) -> 'JSObject':
        pass
        

    @staticmethod
    def writeS8(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeU8(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeS16(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeU16(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeS32(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeU32(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeS64(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeU64(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeShort(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeUShort(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeInt(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeUInt(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeLong(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeULong(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeFloat(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeDouble(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeByteArray(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeUtf8String(address, value) -> 'JSObject':
        pass
        

    @staticmethod
    def writeUtf16String(address, value) -> 'JSObject':
        pass
        
class Cloak:

    @staticmethod
    def addThread(id) -> 'JSObject':
        pass
        

    @staticmethod
    def removeThread(id) -> 'JSObject':
        pass
        

    @staticmethod
    def hasCurrentThread() -> 'JSObject':
        pass
        

    @staticmethod
    def hasThread(id) -> 'JSObject':
        pass
        

    @staticmethod
    def addRange(range) -> 'JSObject':
        pass
        

    @staticmethod
    def removeRange(range) -> 'JSObject':
        pass
        

    @staticmethod
    def hasRangeContaining(address) -> 'JSObject':
        pass
        

    @staticmethod
    def clipRange(range) -> 'JSObject':
        pass
        

    @staticmethod
    def addFileDescriptor(fd) -> 'JSObject':
        pass
        

    @staticmethod
    def removeFileDescriptor(fd) -> 'JSObject':
        pass
        

    @staticmethod
    def hasFileDescriptor(fd) -> 'JSObject':
        pass
        
class ObjC:
    available = None

    api = None

    classes = None

    protocols = None

    mainQueue = None


    @staticmethod
    def schedule(queue, work) -> 'JSObject':
        pass
        

    @staticmethod
    def implement(method, fn) -> 'JSObject':
        pass
        

    @staticmethod
    def registerProxy(spec) -> 'JSObject':
        pass
        

    @staticmethod
    def registerClass(spec) -> 'JSObject':
        pass
        

    @staticmethod
    def registerProtocol(spec) -> 'JSObject':
        pass
        

    @staticmethod
    def bind(obj, data) -> 'JSObject':
        pass
        

    @staticmethod
    def unbind(obj) -> 'JSObject':
        pass
        

    @staticmethod
    def getBoundData(obj) -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateLoadedClasses(options, callbacks) -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateLoadedClassesSync(options) -> 'JSObject':
        pass
        

    @staticmethod
    def choose(specifier, callbacks) -> 'JSObject':
        pass
        

    @staticmethod
    def chooseSync(specifier) -> 'JSObject':
        pass
        

    @staticmethod
    def selector(name) -> 'JSObject':
        pass
        

    @staticmethod
    def selectorAsString(sel) -> 'JSObject':
        pass
        
class Java:
    available = None

    androidVersion = None

    ACC_PUBLIC = None

    ACC_PRIVATE = None

    ACC_PROTECTED = None

    ACC_STATIC = None

    ACC_FINAL = None

    ACC_SYNCHRONIZED = None

    ACC_BRIDGE = None

    ACC_VARARGS = None

    ACC_NATIVE = None

    ACC_ABSTRACT = None

    ACC_STRICT = None

    ACC_SYNTHETIC = None

    vm = None

    classFactory = None


    @staticmethod
    def synchronized(obj, fn) -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateLoadedClasses(callbacks) -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateLoadedClassesSync() -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateClassLoaders(callbacks) -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateClassLoadersSync() -> 'JSObject':
        pass
        

    @staticmethod
    def enumerateMethods(query) -> 'JSObject':
        pass
        

    @staticmethod
    def scheduleOnMainThread(fn) -> 'JSObject':
        pass
        

    @staticmethod
    def perform(fn) -> 'JSObject':
        pass
        

    @staticmethod
    def performNow(fn) -> 'JSObject':
        pass
        

    @staticmethod
    def use(className) -> 'JSObject':
        pass
        

    @staticmethod
    def openClassFile(filePath) -> 'JSObject':
        pass
        

    @staticmethod
    def choose(className, callbacks) -> 'JSObject':
        pass
        

    @staticmethod
    def retain(obj) -> 'JSObject':
        pass
        

    @staticmethod
    def cast(handle, klass) -> 'JSObject':
        pass
        

    @staticmethod
    def array(type, elements) -> 'JSObject':
        pass
        

    @staticmethod
    def backtrace(options) -> 'JSObject':
        pass
        

    @staticmethod
    def isMainThread() -> 'JSObject':
        pass
        

    @staticmethod
    def registerClass(spec) -> 'JSObject':
        pass
        

    @staticmethod
    def deoptimizeEverything() -> 'JSObject':
        pass
        

    @staticmethod
    def deoptimizeBootImage() -> 'JSObject':
        pass
        
