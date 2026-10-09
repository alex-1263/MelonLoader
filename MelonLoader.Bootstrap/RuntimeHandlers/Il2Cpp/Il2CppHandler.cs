using MelonLoader.Bootstrap.Utils;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using MelonLoader.Bootstrap.RuntimeHandlers.Dotnet;

namespace MelonLoader.Bootstrap.RuntimeHandlers.Il2Cpp;

internal static class Il2CppHandler
{
    private static Il2CppLib il2cpp = null!;
    private static bool il2cppInitDone;
    private static bool invokeStarted;

    /// <summary>
    /// Dobby trampoline for the original il2cpp_init while it is inline-hooked by
    /// WineIl2CppHook (Wine path). Zero on native Windows, where il2cpp.Init points
    /// at the untouched export.
    /// </summary>
    internal static nint Il2CppInitTrampoline;
    private static Il2CppLib.InitFn? _trampolineInit;

    internal static nint GetInitDetourPtr()
        => Marshal.GetFunctionPointerForDelegate(Il2CPPInitDetourFn);

    private static nint CallIl2CppInit(nint a)
    {
        if (Il2CppInitTrampoline != nint.Zero)
        {
            _trampolineInit ??= Marshal.GetDelegateForFunctionPointer<Il2CppLib.InitFn>(Il2CppInitTrampoline);
            return _trampolineInit(a);
        }
        return il2cpp.Init(a);
    }

    private static readonly Il2CppLib.InitFn Il2CPPInitDetourFn = InitDetour;
    private static readonly Il2CppLib.RuntimeInvokeFn InvokeDetourFn = InvokeDetour;
    internal static readonly Dictionary<string, (Action<nint> InitMethod, IntPtr detourPtr)> SymbolRedirects = new()
    {
        { "il2cpp_init", (Initialize, Marshal.GetFunctionPointerForDelegate(Il2CPPInitDetourFn))},
        { "il2cpp_runtime_invoke", (Initialize, Marshal.GetFunctionPointerForDelegate(InvokeDetourFn))},
    };

    public static void Initialize(nint handle)
    {
        var il2cppLib = Il2CppLib.TryLoad(handle);
        if (il2cppLib is null)
        {
            Core.Logger.Error("Could not load il2cpp");
            return;
        }

        il2cpp = il2cppLib;
    }

    /// <summary>
    /// Wine path: GameAssembly base recorded by the loader notification callback;
    /// used to lazily run Initialize inside InitDetour (safe thread context)
    /// instead of inside the OS loader lock.
    /// </summary>
    internal static nint PendingGameAssemblyBase;

    internal static nint InitDetour(nint a)
    {
        if (il2cpp == null! && PendingGameAssemblyBase != nint.Zero)
            Initialize(PendingGameAssemblyBase);

        if (il2cppInitDone)
            return CallIl2CppInit(a);

        ConsoleHandler.ResetHandles();
        MelonDebug.Log("In init detour");

        var domain = CallIl2CppInit(a);

        DotnetHandler.Initialize();
        il2cppInitDone = true;

        return domain;
    }

    internal static nint InvokeDetour(nint method, nint obj, nint args, nint exc)
    {
        var result = il2cpp.RuntimeInvoke(method, obj, args, exc);
        if (invokeStarted)
            return result;

        var name = il2cpp.GetMethodName(method);
        if (name == null || !name.Contains("Internal_ActiveSceneChanged"))
            return result;

        invokeStarted = true;
        MelonDebug.Log("Invoke hijacked");

        DotnetHandler.Start();

        return result;
    }
}