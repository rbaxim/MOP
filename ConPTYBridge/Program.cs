// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 rbaxim
// Licensed under the Apache License, Version 2.0
// See LICENSE file in the project root for details
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Moppy.ConPTY
{
    public sealed class ConPTYInstance : IAsyncDisposable
    {
        // ===============================
        // Win32 Constants
        // ===============================

        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
        private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        private const uint STILL_ACTIVE = 259;

        // ===============================
        // Structs
        // ===============================

        [StructLayout(LayoutKind.Sequential)]
        public struct COORD
        {
            public short X;
            public short Y;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        // ===============================
        // Win32 Imports
        // ===============================

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int CreatePseudoConsole(
            COORD size,
            SafeFileHandle hInput,
            SafeFileHandle hOutput,
            uint flags,
            out IntPtr phPC);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void ClosePseudoConsole(IntPtr hPC);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            uint dwFlags,
            ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void DeleteProcThreadAttributeList(
            IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreateProcess(
            string? lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,
            ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeProcess(
            IntPtr hProcess,
            out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        // ===============================
        // Fields
        // ===============================

        private IntPtr _hPC;
        private IntPtr _hProcess;

        private readonly FileStream _stdin;
        private readonly FileStream _stdout;

        private readonly CancellationTokenSource _cts = new();

        public int Pid { get; private set; }

        // ===============================
        // Constructor
        // ===============================

        public ConPTYInstance(
            SafeFileHandle inputWriteEnd,
            SafeFileHandle outputReadEnd)
        {
            // MUST be overlapped handles
            _stdin = new FileStream(inputWriteEnd, FileAccess.Write, 0, true);
            _stdout = new FileStream(outputReadEnd, FileAccess.Read, 0, true);
        }

        // ===============================
        // PTY Creation
        // ===============================

        public void Create(short width, short height,
                           SafeFileHandle inputReadEnd,
                           SafeFileHandle outputWriteEnd)
        {
            var size = new COORD { X = width, Y = height };

            int hr = CreatePseudoConsole(
                size,
                inputReadEnd,
                outputWriteEnd,
                0,
                out _hPC);

            if (hr != 0)
                throw new InvalidOperationException($"CreatePseudoConsole failed: {hr}");
        }

        // ===============================
        // Process Start
        // ===============================

        public void Start(string commandLine, string cwd)
        {
            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();

            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);

            si.lpAttributeList = Marshal.AllocHGlobal(size);

            if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref size))
                throw new InvalidOperationException("Init attr list failed");

            IntPtr pConsole = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(pConsole, _hPC);

            if (!UpdateProcThreadAttribute(
                si.lpAttributeList,
                0,
                (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                pConsole,
                IntPtr.Size,
                IntPtr.Zero,
                IntPtr.Zero))
                throw new InvalidOperationException("Update attr failed");

            if (!CreateProcess(
                null,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                IntPtr.Zero,
                cwd,
                ref si,
                out var pi))
                throw new InvalidOperationException(
                    $"CreateProcess failed: {Marshal.GetLastWin32Error()}");

            Pid = pi.dwProcessId;
            _hProcess = pi.hProcess;

            CloseHandle(pi.hThread);
            DeleteProcThreadAttributeList(si.lpAttributeList);
            Marshal.FreeHGlobal(si.lpAttributeList);
            Marshal.FreeHGlobal(pConsole);
        }

        // ===============================
        // Async IO
        // ===============================

        public ValueTask WriteAsync(
            ReadOnlyMemory<byte> data,
            CancellationToken token = default)
        {
            return _stdin.WriteAsync(data, token);
        }

        public ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken token = default)
        {
            return _stdout.ReadAsync(buffer, token);
        }

        public bool IsAlive()
        {
            if (GetExitCodeProcess(_hProcess, out uint code))
                return code == STILL_ACTIVE;

            return false;
        }

        // ===============================
        // Cleanup
        // ===============================

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();

            await _stdin.DisposeAsync();
            await _stdout.DisposeAsync();

            if (_hPC != IntPtr.Zero)
                ClosePseudoConsole(_hPC);

            if (_hProcess != IntPtr.Zero)
                CloseHandle(_hProcess);
        }
    }
}

// thank you for reading my pain. visuallized as C#