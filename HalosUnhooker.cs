using System;
using System.Diagnostics;
using System.Linq;
using System.IO;
using System.Reflection;
using System.Text;
using System.Runtime.InteropServices;

public class HalosUnhooker {

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static bool CheckStubIntegrity(byte[] stub) {
        return (stub[0] == 0x4c && stub[1] == 0x8b && stub[2] == 0xd1 && stub[3] == 0xb8 && stub[6] == 0x00 && stub[7] == 0x00 && stub[18] == 0x0f && stub[19] == 0x05);
    }

    public static bool Unhook(IntPtr ModuleBase) {
        if (ModuleBase == IntPtr.Zero) 
            ModuleBase = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => "ntdll.dll".Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);

        try {
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b) {
                pExport = OptHeader + 0x60;
            }else {
                pExport = OptHeader + 0x70;
            }

            // search for .TEXT section and change the memory protection
            uint oldProtect = 0;
            Int32 TextSectionSize = 0;
            Int32 TextSectionRVA = 0;
            IntPtr SectionHeaderBaseAddr = ModuleBase + Marshal.ReadInt32((IntPtr)(ModuleBase + 0x3C)) + 0x18 + Marshal.ReadInt16((IntPtr)(ModuleBase + Marshal.ReadInt32((IntPtr)(ModuleBase + 0x3C)) + 20));
            Int16 NumberOfSections = Marshal.ReadInt16(ModuleBase + Marshal.ReadInt32((IntPtr)(ModuleBase + 0x3C)) + 6);
            for (int i = 0; i < NumberOfSections; i++) {
                IntPtr CurrentSectionHeaderAddr = SectionHeaderBaseAddr + (i * 40);
                string CurrentSectionHeaderName = Marshal.PtrToStringAnsi(CurrentSectionHeaderAddr);
                if (CurrentSectionHeaderName == ".text") {
                    TextSectionSize = Marshal.ReadInt32(CurrentSectionHeaderAddr + 8);
                    TextSectionRVA = Marshal.ReadInt32(CurrentSectionHeaderAddr + 12);
                    VirtualProtect((IntPtr)(ModuleBase.ToInt64() + TextSectionRVA), (UIntPtr)TextSectionSize, 0x40, out oldProtect);
                    break;
                }
            }

            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            for (int i = 0; i < NumberOfNames; i++) {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (!FunctionName.StartsWith("Nt") || FunctionName.StartsWith("Ntdll")) {
                    continue; // skip Non-Nt functions
                }

                Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                IntPtr FunctionAddress = (IntPtr)((Int64)ModuleBase + FunctionRVA);

                // copy function opcode
                byte[] FunctionOpcode = new byte[24];
                Marshal.Copy(FunctionAddress, FunctionOpcode, 0, 24);
                if (!CheckStubIntegrity(FunctionOpcode)) { 
                    Int16 SyscallID = -1;
                    // check for neighbouring syscall up
                    for (int z = 1; z < 50; z++) {
                        Marshal.Copy((FunctionAddress + (-32 * z)), FunctionOpcode, 0, 24);
                        if (CheckStubIntegrity(FunctionOpcode)) {
                            SyscallID = (Int16)(((byte)FunctionOpcode[5] << 4) | (byte)FunctionOpcode[4] + z);
                            break;
                        }
                    }

                    // check for neighbouring syscall down
                    if (SyscallID == -1) {
                        for (int z = 1; z < 50; z++) {
                            Marshal.Copy((FunctionAddress + (32 * z)), FunctionOpcode, 0, 24);
                            if (CheckStubIntegrity(FunctionOpcode)) {
                                SyscallID = (Int16)(((byte)FunctionOpcode[5] << 4) | (byte)FunctionOpcode[4] - z);
                                break;
                            }
                        }
                    }

                    // crafting the new stub
                    byte[] newstub = new byte[24] {
                        Convert.ToByte("4C", 16), Convert.ToByte("8B", 16), Convert.ToByte("D1", 16),
                        Convert.ToByte("B8", 16), (byte)SyscallID, (byte)(SyscallID >> 8), Convert.ToByte("00", 16), Convert.ToByte("00", 16),
                        Convert.ToByte("F6", 16), Convert.ToByte("04", 16), Convert.ToByte("25", 16), Convert.ToByte("08", 16), Convert.ToByte("03", 16), Convert.ToByte("FE", 16), Convert.ToByte("7F", 16), Convert.ToByte("01", 16),
                        Convert.ToByte("75", 16), Convert.ToByte("03", 16),
                        Convert.ToByte("0F", 16), Convert.ToByte("05", 16),
                        Convert.ToByte("C3", 16),
                        Convert.ToByte("CD", 16), Convert.ToByte("2E", 16),
                        Convert.ToByte("C3", 16)
                    };

                    // place the new stub to the address
                    Marshal.Copy(newstub, 0, FunctionAddress, 24);
                }
            }

            // revert the memory protection of the .TEXT section
            uint newProtect = 0;
            VirtualProtect((IntPtr)(ModuleBase.ToInt64() + TextSectionRVA), (UIntPtr)TextSectionSize, oldProtect, out newProtect);
        }
        catch(Exception e) {
            Console.WriteLine("[HalosUnhooker] Exception : {0}", e.Message);
            return false;
        }
        return true;
    }
}
