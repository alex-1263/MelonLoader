using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using MelonLoader.Bootstrap.RuntimeHandlers.Il2Cpp;
using MelonLoader.Bootstrap.Utils;

namespace MelonLoader.Bootstrap;

#if WINDOWS
/// <summary>
/// Wine/Proton workaround: wine's loader binds well-known system imports through
/// internal fast paths, so neither the patched IAT entry inside UnityPlayer.dll nor
/// an inline hook on kernel32.GetProcAddress is ever reached by external modules.
/// Instead, listen for the OS loader notification of GameAssembly.dll being mapped
/// and Dobby-hook the il2cpp_init export itself (module-to-module calls through a
/// PE export always go through the patched function body).
///
/// The loader notification callback runs inside the OS loader lock: it must not
/// allocate, log, or otherwise touch the GC. It therefore only does a
/// byte-by-byte name comparison and, on a match, records the module base and
/// installs the Dobby hook. All managed initialisation is deferred to the first
/// invocation of Il2CppHandler.InitDetour, which runs on a normal thread.
/// </summary>
internal static unsafe partial class WineIl2CppHook
{
    private const uint LdrDllNotificationReasonLoaded = 1;

    private static bool _installed;
    private static nint _initDetourPtr; // cached outside the loader lock

    [LibraryImport("ntdll.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    private static partial int LdrRegisterDllNotification(uint flags, nint notification, nint context, out nint cookie);

    [LibraryImport("kernel32.dll", EntryPoint = "OutputDebugStringA", StringMarshalling = StringMarshalling.Utf8)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    private static partial void DebugLog(string msg);

    [LibraryImport("*", EntryPoint = "DobbyHook")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int DobbyHook(nint target, nint detour, ref nint original);

    internal static void Install()
    {
        if (_installed)
            return;
        _installed = true;

        _initDetourPtr = Il2CppHandler.GetInitDetourPtr();

        var callback = (nint)(delegate* unmanaged[Stdcall]<uint, nint, nint, void>)&DllNotificationCallback;
        if (LdrRegisterDllNotification(0, callback, nint.Zero, out _) != 0)
        {
            Core.Logger.Error("Failed to register LdrDllNotification for Wine il2cpp hook");
            return;
        }

        Core.Logger.Msg("Wine il2cpp hook installed (LdrDllNotification)");
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static void DllNotificationCallback(uint reason, nint data, nint context)
    {
        // Runs inside the loader lock: no allocations, no logging, no exceptions.
        if (reason != LdrDllNotificationReasonLoaded)
            return;
        if (Il2CppHandler.PendingGameAssemblyBase != nint.Zero)
            return;

        // LDR_DLL_LOADED_NOTIFICATION_DATA (x64):
        //   +8  PCUNICODE_STRING FullDllName
        //   +16 PCUNICODE_STRING BaseDllName
        //   +24 PVOID DllBase
        // UNICODE_STRING (x64): +0 USHORT Length (bytes), +8 PWSTR Buffer
        var nameStruct = Marshal.ReadIntPtr(data + 16);
        if (nameStruct == nint.Zero)
            return;
        DebugLog(Marshal.PtrToStringUni(Marshal.ReadIntPtr(nameStruct, 8), Marshal.ReadInt16(nameStruct) / 2) ?? "?");

        int length = Marshal.ReadInt16(nameStruct);
        var buffer = Marshal.ReadIntPtr(nameStruct, 8);
        // "GameAssembly.dll" = 16 chars; Length normally excludes the NUL (=32),
        // but tolerate a value that includes it (=34).
        if ((length != 32 && length != 34) || buffer == nint.Zero)
            return;

        // Case-insensitive compare against L"GameAssembly.dll" without allocating.
        // (length 34 includes the terminating NUL, which we verify as well)
        short c;
        if ((c = Marshal.ReadInt16(buffer)) != 'G' && c != 'g') return;
        if ((c = Marshal.ReadInt16(buffer, 2)) != 'a' && c != 'A') return;
        if ((c = Marshal.ReadInt16(buffer, 4)) != 'm' && c != 'M') return;
        if ((c = Marshal.ReadInt16(buffer, 6)) != 'e' && c != 'E') return;
        if ((c = Marshal.ReadInt16(buffer, 8)) != 'A' && c != 'a') return;
        if ((c = Marshal.ReadInt16(buffer, 10)) != 's' && c != 'S') return;
        if ((c = Marshal.ReadInt16(buffer, 12)) != 's' && c != 's') return;
        if ((c = Marshal.ReadInt16(buffer, 14)) != 'e' && c != 'E') return;
        if ((c = Marshal.ReadInt16(buffer, 16)) != 'm' && c != 'M') return;
        if ((c = Marshal.ReadInt16(buffer, 18)) != 'b' && c != 'B') return;
        if ((c = Marshal.ReadInt16(buffer, 20)) != 'l' && c != 'L') return;
        if ((c = Marshal.ReadInt16(buffer, 22)) != 'y' && c != 'Y') return;
        if (Marshal.ReadInt16(buffer, 24) != '.') return;
        if ((c = Marshal.ReadInt16(buffer, 26)) != 'd' && c != 'D') return;
        if ((c = Marshal.ReadInt16(buffer, 28)) != 'l' && c != 'L') return;
        if ((c = Marshal.ReadInt16(buffer, 30)) != 'l' && c != 'L') return;
        if (length == 34 && Marshal.ReadInt16(buffer, 32) != 0) return;

        var dllBase = Marshal.ReadIntPtr(data + 24);
        if (dllBase == nint.Zero)
            return;

        // Resolve the export through the raw ntdll path (no managed delegate here).
        DebugLog("[wine-hook] GameAssembly matched");
        var init = ResolveExport(dllBase, "il2cpp_init");
        if (init == nint.Zero)
        {
            DebugLog("[wine-hook] il2cpp_init NOT FOUND");
            return;
        }

        nint trampoline = nint.Zero;
        if (DobbyHook(init, _initDetourPtr, ref trampoline) != 0)
            return;

        // Publish for the lazy initialisation inside InitDetour.
        Il2CppHandler.Il2CppInitTrampoline = trampoline;
        DebugLog($"[wine-hook] dobby hooked il2cpp_init trampoline={trampoline:X}");
        Il2CppHandler.PendingGameAssemblyBase = dllBase;
    }

    private static nint ResolveExport(nint module, string name)
    {
        // WindowsNative.GetProcAddress marshals the name (allocates); use it only
        // via this indirection which is called outside the hot compare path —
        // still inside the loader lock, but a single small allocation-free
        // LibraryImport call with a Utf8 literal needs no marshalling buffer.
        return WindowsNative.GetProcAddress(module, name);
    }
}
#endif
