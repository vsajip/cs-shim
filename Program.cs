/*
 * Copyright 2021 Red Dove Consultants Limited
 *
 * Author: Vinay Sajip <vinay_sajip@yahoo.co.uk>
 *
 * License: BSD-3-Clause
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

namespace Shim
{
    using System;
    using System.ComponentModel;
    using System.Runtime.ConstrainedExecution;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Text;

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectBasicLimitInformation
    {
        public Int64 PerProcessUserTimeLimit;
        public Int64 PerJobUserTimeLimit;
        public JobObjectlimit LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public UInt32 ActiveProcessLimit;
        public Int64 Affinity;
        public UInt32 PriorityClass;
        public UInt32 SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IoCounters
    {
        public UInt64 ReadOperationCount;
        public UInt64 WriteOperationCount;
        public UInt64 OtherOperationCount;
        public UInt64 ReadTransferCount;
        public UInt64 WriteTransferCount;
        public UInt64 OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    public enum JobObjectInfoType
    {
# if UNUSED
        BasicAccountingInformation = 1,
        BasicLimitInformation = 2,
        BasicProcessIdList = 3,
        BasicUiRestrictions = 4,
        SecurityLimitInformation = 5,
        EndOfJobTimeInformation = 6,
        AssociateCompletionPortInformation = 7,
        BasicAndIoAccountingInformation = 8,
        GroupInformation = 11,
# endif
        ExtendedLimitInformation = 9
    }

    public enum StdioHandleType
    {
        STD_INPUT_HANDLE = -10,
        STD_OUTPUT_HANDLE = -11,
        STD_ERROR_HANDLE = -12
    }

    [Flags]
    public enum JobObjectlimit
    {
# if UNUSED
        JOB_OBJECT_LIMIT_WORKINGSET = 0x0001,
        JOB_OBJECT_LIMIT_PROCESS_TIME = 0x0002,
        JOB_OBJECT_LIMIT_JOB_TIME = 0x0004,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x0008,
        JOB_OBJECT_LIMIT_AFFINITY = 0x0010,
        JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x0020,
        JOB_OBJECT_LIMIT_PRESERVE_JOB_TIME = 0x0040,
        JOB_OBJECT_LIMIT_SCHEDULING_CLASS = 0x0080,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x0100,
        JOB_OBJECT_LIMIT_JOB_MEMORY = 0x0200,
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x0400,
        JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x0800,
        JOB_OBJECT_LIMIT_SUBSET_AFFINITY = 0x4000,
# endif
        JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x1000,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct StartupInfo : IDisposable
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;

        public void Dispose() {}
    }

    [Flags]
    public enum DuplicateOptions
    {
# if UNUSED
        DUPLICATE_CLOSE_SOURCE = (0x00000001),// Closes the source handle. This occurs regardless of any error status returned.
# endif
        DUPLICATE_SAME_ACCESS = (0x00000002), //Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.
    }

    [Flags]
    public enum StartFlags
    {
# if UNUSED
        STARTF_USESHOWWINDOW = 0x00000001,
        STARTF_USESIZE = 0x00000002,
        STARTF_USEPOSITION = 0x00000004,
        STARTF_USECOUNTCHARS = 0x00000008,
        STARTF_USEFILLATTRIBUTE = 0x00000010,
        STARTF_RUNFULLSCREEN = 0x00000020,  // ignored for non-x86 platforms
        STARTF_FORCEONFEEDBACK = 0x00000040,
        STARTF_FORCEOFFFEEDBACK = 0x00000080,
# endif
        STARTF_USESTDHANDLES = 0x00000100,
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    class NativeMethods
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string name);

        [DllImport("kernel32.dll")]
        //static extern bool QueryInformationJobObject(IntPtr job, JobObjectInfoType infoType,
        //    IntPtr lpJobObjectInfo, int cbJobObjectInfoLength, IntPtr lpReturnLength);
        static extern bool QueryInformationJobObject(IntPtr job, JobObjectInfoType infoType,
            out JobObjectExtendedLimitInformation lpJobObjectInfo, int cbJobObjectInfoLength, out uint lpReturnLength);

        [DllImport("kernel32.dll")]
        static extern bool SetInformationJobObject(IntPtr job, JobObjectInfoType infoType,
            [In] ref JobObjectExtendedLimitInformation lpJobObjectInfo, int cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
            uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int nStdHandle);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,
            uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartupInfo lpStartupInfo, out ProcessInformation
                lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        const UInt32 Infinite = 0xFFFFFFFF;

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll")]
        static extern void ExitProcess(uint uExitCode);

        static void Fail(string message)
        {
            string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
            var msg = string.IsNullOrWhiteSpace(errorMessage) ? message : $"{message}: {errorMessage}";
            throw new ApplicationException(msg);
        }

        static void Main(string[] args)
        {
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            int length = Marshal.SizeOf(typeof(JobObjectExtendedLimitInformation));
            //IntPtr extendedInfoPtr = Marshal.AllocHGlobal(length);
            String target = Resource.Target;
            JobObjectExtendedLimitInformation extendedInfo;

            string startDir = Resource.StartDir;
            if (string.IsNullOrWhiteSpace(startDir))
            {
                startDir = null;
            }
            if (string.IsNullOrWhiteSpace(target))
            {
                throw new ApplicationException("Target not configured");
            }
            uint retLen;
            var ok = QueryInformationJobObject(job, JobObjectInfoType.ExtendedLimitInformation, out extendedInfo, length, out retLen);
            if (!ok)
            {
                Fail("Unable to query job information");
            }
            //JobObjectExtendedLimitInformation extendedInfo = (JobObjectExtendedLimitInformation) Marshal.PtrToStructure(extendedInfoPtr, typeof(JobObjectExtendedLimitInformation));
            extendedInfo.BasicLimitInformation.LimitFlags |=
                JobObjectlimit.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JobObjectlimit.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
            //Marshal.StructureToPtr(extendedInfo, extendedInfoPtr, false);

            ok = SetInformationJobObject(job, JobObjectInfoType.ExtendedLimitInformation, ref extendedInfo, length);
            if (!ok)
            {
                Fail("Unable to set job information");
            }
            IntPtr process = GetCurrentProcess();
            var startupInfo = new StartupInfo();
            ProcessInformation processInfo;
            StringBuilder sb = new StringBuilder(target);
            foreach (var arg in args)
            {
                sb.Append(' ');
                if (!arg.Contains(" "))
                {
                    sb.Append(arg);
                }
                else
                {
                    sb.Append('"');
                    sb.Append(arg);
                    sb.Append('"');
                }
            }

            string cmdLine = sb.ToString();
            startupInfo.cb = Marshal.SizeOf((typeof(StartupInfo)));
            startupInfo.dwFlags = (int) StartFlags.STARTF_USESTDHANDLES;
            var hIn = GetStdHandle((int) StdioHandleType.STD_INPUT_HANDLE);
            var hOut = GetStdHandle((int) StdioHandleType.STD_OUTPUT_HANDLE);
            var hErr = GetStdHandle((int) StdioHandleType.STD_ERROR_HANDLE);
            ok = DuplicateHandle(process, hIn, process, out startupInfo.hStdInput, 0, true, (uint) DuplicateOptions.DUPLICATE_SAME_ACCESS);
            if (!ok)
            {
                Fail("Unable to duplicate stdin");
            }
            ok = DuplicateHandle(process, hOut, process, out startupInfo.hStdOutput, 0, true, (uint) DuplicateOptions.DUPLICATE_SAME_ACCESS);
            if (!ok)
            {
                Fail("Unable to duplicate stdout");
            }
            ok = DuplicateHandle(process, hErr, process, out startupInfo.hStdError, 0, true, (uint) DuplicateOptions.DUPLICATE_SAME_ACCESS);
            if (!ok)
            {
                Fail("Unable to duplicate stderr");
            }
            ok = CreateProcess(null, cmdLine, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, startDir, ref startupInfo, out processInfo);
            if (!ok)
            {
                Fail("Unable to create process");
            }
            ok = AssignProcessToJobObject(job, processInfo.hProcess);
            if (!ok)
            {
                Fail("Unable to assign process to job");
            }
            CloseHandle(processInfo.hThread);
            WaitForSingleObject(processInfo.hProcess, Infinite);
            uint rc;
            ok = GetExitCodeProcess(processInfo.hProcess, out rc);
            if (!ok)
            {
                Fail("Unable to get child exit code");
            }
            ExitProcess(rc);
        }
    }
}
