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
/// </summary>
internal static unsafe partial class WineIl2CppHook
{
    private const uint LdrDllNotificationReasonLoaded = 1;

    [LibraryImport("ntdll.dll")]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvStdcall)])]
    private static partial int LdrRegisterDllNotification(uint flags, nint notification, nint context, out nint cookie);

    private static bool _installed;

    internal static void Install()
    {
        Core.Logger.Msg("[wine-hook] Install enter");
        if (_installed)
            return;
        _installed = true;

        Core.Logger.Msg("[wine-hook] registering LdrDllNotification");
        var callback = (nint)(delegate* unmanaged[Stdcall]<uint, nint, nint, void>)&DllNotificationCallback;
        if (LdrRegisterDllNotification(0, callback, nint.Zero, out _) != 0)
        {
            Core.Logger.Error("Failed to register LdrDllNotification for Wine il2cpp hook");
            return;
        }

        Core.Logger.Msg("[wine-hook] notification registered");
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static void DllNotificationCallback(uint reason, nint data, nint context)
    {
        try
        {
            if (reason != LdrDllNotificationReasonLoaded)
                return;

            var cbName = Marshal.ReadIntPtr(data + 16);
            string? dn = null;
            if (cbName != nint.Zero)
            {
                short l2 = Marshal.ReadInt16(cbName);
                var b2 = Marshal.ReadIntPtr(cbName, 8);
                if (l2 > 0 && b2 != nint.Zero) dn = Marshal.PtrToStringUni(b2, l2 / 2);
            }
            Core.Logger.Msg($"[wine-hook] loaded: {dn ?? "?"}");

            // LDR_DLL_LOADED_NOTIFICATION_DATA (x64):
            //   +0  ULONG Flags (+4 pad)
            //   +8  PCUNICODE_STRING FullDllName
            //   +16 PCUNICODE_STRING BaseDllName
            //   +24 PVOID DllBase
            //   +32 ULONG SizeOfImage
            // UNICODE_STRING (x64): +0 USHORT Length (bytes), +8 PWSTR Buffer
            var baseDllName = Marshal.ReadIntPtr(data + 16);
            if (baseDllName == nint.Zero)
                return;

            short length = Marshal.ReadInt16(baseDllName);
            nint buffer = Marshal.ReadIntPtr(baseDllName, 8);
            if (length <= 0 || buffer == nint.Zero)
                return;

            var name = Marshal.PtrToStringUni(buffer, length / 2);
            if (string.IsNullOrEmpty(name) || !name.Contains("GameAssembly", StringComparison.OrdinalIgnoreCase))
                return;

            var dllBase = Marshal.ReadIntPtr(data + 24);
            HookIl2Cpp(dllBase);
        }
        catch
        {
            // Never let an exception escape a loader notification callback.
        }
    }

    private static bool _hooked;

    private static void HookIl2Cpp(nint dllBase)
    {
        if (_hooked)
            return;
        _hooked = true;

        Core.Logger.Msg($"[wine-hook] GameAssembly mapped at {dllBase:X}, hooking il2cpp_init");
        Il2CppHandler.Initialize(dllBase);

        var init = WindowsNative.GetProcAddress(dllBase, "il2cpp_init");
        if (init == nint.Zero)
        {
            Core.Logger.Error("Wine hook: could not resolve il2cpp_init in GameAssembly");
            return;
        }

        try
        {
            Il2CppHandler.Il2CppInitTrampoline = Dobby.HookAttach(init, Il2CppHandler.GetInitDetourPtr());
        }
        catch (AccessViolationException e)
        {
            Core.Logger.Error($"Wine hook: Dobby failed to hook il2cpp_init: {e.Message}");
            return;
        }

        Core.Logger.Msg("Dobby hooked il2cpp_init on GameAssembly (Wine path)");
    }
}
#endif
