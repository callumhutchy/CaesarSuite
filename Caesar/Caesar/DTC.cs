using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Caesar
{
    public class DTC
    {
        public enum DTCStatusByte : uint
        {
            TestFailedAtRequestTime = 0x01,
            TestFailedAtCurrentCycle = 0x02,
            PendingDTC = 0x04,
            ConfirmedDTC = 0x08,
            TestIncompleteSinceLastClear = 0x10,
            TestFailedSinceLastClear = 0x20,
            TestIncompleteAtCurrentCycle = 0x40,
            WarningIndicatorActive = 0x80,
        }

        // see : const char *__cdecl DIGetComfortErrorCode(DI_ECUINFO *ecuh, unsigned int dtcIndex)
        public string Qualifier;


        [Newtonsoft.Json.JsonIgnore]
        public int Description_CTF;


        [Newtonsoft.Json.JsonIgnore]
        public int Reference_CTF;


        [Newtonsoft.Json.JsonIgnore]
        public int XrefStart = -1;

        [Newtonsoft.Json.JsonIgnore]
        public int XrefCount = -1;

        private long BaseAddress;


        [Newtonsoft.Json.JsonIgnore]
        public int PoolIndex;

        Dictionary<string, string> troubleCodeDict = new Dictionary<string, string>()
        {
            {"P0", "0" },
            {"P1", "1" },
            {"P2", "2" },
            {"P3", "3" },
            {"C0", "4" },
            {"C1", "5" },
            {"C2", "6" },
            {"C3", "7" },
            {"B0", "8" },
            {"B1", "9" },
            {"B2", "A" },
            {"B3", "B" },
            {"U0", "C" },
            {"U1", "D" },
            {"U2", "E" },
            {"U3", "F" }
        };

        public string troubleCode;

        [Newtonsoft.Json.JsonIgnore]
        public ECU ParentECU;


        [Newtonsoft.Json.JsonIgnore]
        public CTFLanguage Language;

        public string Description { get { return Language.GetString(Description_CTF); } }
        public string Reference { get { return Language.GetString(Reference_CTF); } }

        public void Restore(CTFLanguage language, ECU parentEcu)
        {
            ParentECU = parentEcu;
            Language = language;
        }

        public DTC() { }

        public DTC(BinaryReader reader, CTFLanguage language, long baseAddress, int poolIndex, ECU parentEcu)
        {
            ParentECU = parentEcu;
            PoolIndex = poolIndex;
            BaseAddress = baseAddress;
            Language = language;
            reader.BaseStream.Seek(baseAddress, SeekOrigin.Begin);

            ulong bitflags = reader.ReadUInt16();

            Qualifier = CaesarReader.ReadBitflagStringWithReader(ref bitflags, reader, baseAddress);

            if (Qualifier.Length > 4 && Char.IsLetter(Qualifier[0]))
                troubleCode = "0x" + troubleCodeDict[Qualifier.Substring(0, 2)] + Qualifier.Substring(2);
            else
                troubleCode = "0x" + Qualifier;

            Description_CTF = CaesarReader.ReadBitflagInt32(ref bitflags, reader, -1);
            Reference_CTF = CaesarReader.ReadBitflagInt32(ref bitflags, reader, -1);
#if DEBUG
            if (bitflags > 0)
            {
                Console.WriteLine($"DTC {Qualifier} has additional unparsed fields : 0x{bitflags:X}");
            }
#endif
        }
        /*
        public string GetDescription() 
        {
            return Language.GetString(Description_CTF);
        }
        */
        public static DTC FindDTCById(string id, ECUVariant variant)
        {
            foreach (DTC dtc in variant.DTCs)
            {
                if (dtc.Qualifier.EndsWith(id))
                {
                    return dtc;
                }
            }
            return null;
        }
        public void PrintDebug()
        {
            Console.WriteLine($"DTC: {Qualifier}: {Language.GetString(Description_CTF)} : {Language.GetString(Reference_CTF)}");
        }
    }
}
