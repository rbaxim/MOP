// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 rbaxim
// Licensed under the Apache License, Version 2.0
// See LICENSE file in the project root for details
using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Moppy.ConPTY
{
    public class ConPTYInstance : IDisposable
    {
        // --- 1. Constants & Structs (The "Scary" definitions) ---
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const int PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
        private const uint ENABLE_ECHO_INPUT = 0x0004;

        [StructLayout(LayoutKind.Sequential)]
        public struct COORD { public short X; public short Y; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
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
        struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        // --- 2. Win32 Imports ---
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int CreatePseudoConsole(COORD size, SafeFileHandle hInput, SafeFileHandle hOutput, uint dwFlags, out IntPtr phPC);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern void ClosePseudoConsole(IntPtr hPC);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcess(string? lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, string? lpEnvironment, string? lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, uint dwFlags, ref IntPtr lpSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool PeekNamedPipe(SafeFileHandle hNamedPipe, IntPtr lpBuffer, uint nBufferSize, IntPtr lpBytesRead, out uint lpTotalBytesAvail, IntPtr lpBytesLeftThisMessage);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void CloseHandle(IntPtr hObject);

        // --- 3. Fields & Properties ---
        private IntPtr _hPC = IntPtr.Zero;
        private FileStream? _writer;
        private FileStream? _reader;

        private readonly BlockingCollection<byte[]> _writeQueue = new();

        private readonly ConcurrentQueue<byte[]> _readQueue = new();
        
        public int Pid { get; private set; }
        public IntPtr _hProcess = IntPtr.Zero;
        public string Cwd { get; set; } = Directory.GetCurrentDirectory();
        public Dictionary<string, string> EnvVars { get; set; } = new Dictionary<string, string>();

        private bool _readerFailed = false;

        // Constructor
        public ConPTYInstance(SafeFileHandle writeEnd, SafeFileHandle readEnd)
        {
            _writer = new FileStream(writeEnd, FileAccess.Write, 4096, isAsync: true);
            _reader = new FileStream(readEnd, FileAccess.Read, 4096, isAsync: true);

            StartWriterThread();
            StartReaderThread();
        }

        // --- 4. Logic Methods ---

        private static void SplitCommandLine(string commandLine, out string exePath, out string fullCommandLine)
        {
            commandLine = commandLine.Trim();

            if (commandLine.StartsWith("\""))
            {
                int end = commandLine.IndexOf('"', 1);
                if (end < 0)
                    throw new ArgumentException("Unterminated quote in command line");

                exePath = commandLine.Substring(1, end - 1);
                string rest = commandLine.Substring(end + 1).TrimStart();
                fullCommandLine = $"\"{exePath}\" {rest}";
            }
            else
            {
                int space = commandLine.IndexOf(' ');
                if (space < 0)
                {
                    exePath = commandLine;
                    fullCommandLine = $"\"{exePath}\"";
                }
                else
                {
                    exePath = commandLine.Substring(0, space);
                    string rest = commandLine.Substring(space + 1);
                    fullCommandLine = $"\"{exePath}\" {rest}";
                }
            }
        }


        public void Create(short width, short height, SafeFileHandle ptyInputRead, SafeFileHandle ptyOutputWrite, uint flags = 0)
        {
            var size = new COORD { X = width, Y = height };
            int res = CreatePseudoConsole(size, ptyInputRead, ptyOutputWrite, flags, out _hPC);
            if (res != 0) throw new Exception("ConPTY Creation Failed");
        }

        public void Start(string commandLine, string cwd, Dictionary<string, string>? envVars = null)
        {
            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();

            // Init attribute list
            IntPtr lpSize = IntPtr.Zero;
            IntPtr hPCValue = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(hPCValue, _hPC);
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
            si.lpAttributeList = Marshal.AllocHGlobal(lpSize);

            if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref lpSize))
                throw new Exception($"InitializeProcThreadAttributeList failed: {Marshal.GetLastWin32Error()}");

            if (!UpdateProcThreadAttribute(
                    si.lpAttributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                    hPCValue,
                    IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero))
            {
                throw new Exception($"UpdateProcThreadAttribute failed: {Marshal.GetLastWin32Error()}");
            }

            var pi = new PROCESS_INFORMATION();

            // --------------------------------------------------
            // Build environment block (from parameter)
            // --------------------------------------------------
            string? env = null;
            if (envVars != null && envVars.Count > 0)
            {
                var sb = new StringBuilder();
                foreach (var kvp in envVars)
                {
                    sb.Append(kvp.Key);
                    sb.Append('=');
                    sb.Append(kvp.Value);
                    sb.Append('\0');
                }
                sb.Append('\0'); // double-null terminate
                env = sb.ToString();
            }

            // --------------------------------------------------
            // Extract exe path + full command line
            // --------------------------------------------------
            string exePath;
            string fullCmd;

            commandLine = commandLine.Trim();

            if (commandLine.StartsWith("\""))
            {
                int end = commandLine.IndexOf('"', 1);
                if (end == -1)
                    throw new ArgumentException("Invalid quoted command line");

                exePath = commandLine.Substring(1, end - 1);
                fullCmd = commandLine;
            }
            else
            {
                int firstSpace = commandLine.IndexOf(' ');
                if (firstSpace == -1)
                {
                    exePath = commandLine;
                    fullCmd = commandLine;
                }
                else
                {
                    exePath = commandLine.Substring(0, firstSpace);
                    fullCmd = commandLine;
                }
            }

            if (!File.Exists(exePath))
                throw new FileNotFoundException($"Executable not found: {exePath}");

            // --------------------------------------------------
            // Create process
            // --------------------------------------------------
            bool ok = CreateProcess(
                exePath,   // lpApplicationName (EXPLICIT)
                fullCmd,   // lpCommandLine (FULL STRING)
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                env,       // environment block from parameter
                cwd,
                ref si,
                out pi
            );


            if (!ok)
            {
                int err = Marshal.GetLastWin32Error();
                throw new Exception(
                    $"CreateProcess Failed: {err}\n" +
                    $"exePath = '{exePath}'\n" +
                    $"fullCmd = '{fullCmd}'\n" +
                    $"Cwd = '{Cwd}'"
                );
            }

            this.Pid = pi.dwProcessId;
            this._hProcess = pi.hProcess;

            CloseHandle(pi.hThread);

            DeleteProcThreadAttributeList(si.lpAttributeList);
            Marshal.FreeHGlobal(si.lpAttributeList);
            Marshal.FreeHGlobal(hPCValue);
        }

        private void StartWriterThread()
        {
            var t = new Thread(() =>
            {
                foreach (var data in _writeQueue.GetConsumingEnumerable())
                {
                    try
                    {
                        _writer!.Write(data, 0, data.Length);
                        _writer.Flush();
                    }
                    catch { break; }
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        private void StartReaderThread()
        {
            var t = new Thread(() =>
            {
                var buf = new byte[8192];
                while (true)
                {
                    try
                    {
                        int n = _reader!.Read(buf, 0, buf.Length);
                        if (n <= 0) break;

                        var chunk = new byte[n];
                        Buffer.BlockCopy(buf, 0, chunk, 0, n);
                        _readQueue.Enqueue(chunk);
                    }
                    catch (Exception)
                    {
                        _readerFailed = true;
                        break;
                    }
                }
            });
            t.IsBackground = true;
            t.Start();
        }

        public void Write(byte[] data)
        {
            if (_readerFailed)
                throw new IOException("ConPTY reader failed; output pipe is no longer draining.");

            _writeQueue.Add(data);
        }

        public byte[] Read()
        {
            if (_readQueue.TryDequeue(out var data))
                return data;

            return Array.Empty<byte>();
        }

        public void Dispose()
        {
            try
            {
                // Suppress errors during flush/close if the pipe is already broken
                if (_hPC != IntPtr.Zero)
                {
                    ClosePseudoConsole(_hPC);
                    _hPC = IntPtr.Zero;
                }

                _writeQueue.CompleteAdding();
                _writer?.Dispose();
                _reader?.Dispose();

                if (_hProcess != IntPtr.Zero)
                {
                    CloseHandle(_hProcess);
                    _hProcess = IntPtr.Zero;
                }
            }
            catch (Exception) { /* Ignore pipe errors during cleanup */ }

        }

        public uint ExitCode()
        {
            if (_hProcess == IntPtr.Zero) throw new Exception("ConPTY not initialized.");

            if (GetExitCodeProcess(_hProcess, out uint exitCode))
            {
                return exitCode;
            }
            else
            {
                throw new Exception($"GetExitCodeProcess Failed: {Marshal.GetLastWin32Error()}");
            }
        }

        public bool IsAlive()
        {
            uint exitCode = ExitCode();
            return exitCode == 259; // STILL_ACTIVE
        }
    }
}