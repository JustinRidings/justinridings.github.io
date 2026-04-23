using System.Reflection.PortableExecutable;
using System.Text;
using PersonalSite.Data.Models;

namespace PersonalSite.Services;

public static class PEAnalyzer
{
    public static PEAnalysis Analyze(string fileName, byte[] bytes)
    {
        try
        {
            using var ms = new MemoryStream(bytes, writable: false);
            using var pe = new PEReader(ms, PEStreamOptions.PrefetchEntireImage);

            var headers = pe.PEHeaders;
            var coff = headers.CoffHeader;
            var opt = headers.PEHeader;

            var dos = ReadDosHeader(bytes);
            var coffInfo = BuildCoff(coff);
            var optInfo = opt is null ? null : BuildOptional(opt);
            var dataDirs = opt is null ? Array.Empty<DataDirectoryInfo>() : BuildDataDirectories(opt);
            var sections = BuildSections(headers.SectionHeaders);

            var imports = TryReadImports(pe, opt);
            var exports = TryReadExports(pe, opt);
            ClrHeaderInfo? clr = null;
            if (pe.HasMetadata)
            {
                var c = pe.PEHeaders.CorHeader;
                if (c is not null)
                {
                    clr = new ClrHeaderInfo(
                        c.MajorRuntimeVersion,
                        c.MinorRuntimeVersion,
                        c.MetadataDirectory.RelativeVirtualAddress,
                        c.MetadataDirectory.Size,
                        c.Flags.ToString(),
                        c.EntryPointTokenOrRelativeVirtualAddress);
                }
            }

            var summary = BuildSummary(coff, opt, pe, sections);

            return new PEAnalysis(
                fileName,
                bytes.LongLength,
                true,
                null,
                summary,
                dos,
                coffInfo,
                optInfo,
                dataDirs,
                sections,
                imports,
                exports,
                clr);
        }
        catch (BadImageFormatException ex)
        {
            return Failed(fileName, bytes.LongLength, $"Not a valid PE file: {ex.Message}");
        }
        catch (Exception ex)
        {
            return Failed(fileName, bytes.LongLength, $"Parse error: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static PEAnalysis Failed(string name, long size, string error) =>
        new(name, size, false, error,
            new PESummary("?", "?", "?", DateTime.MinValue, false, false, false, false, false, false, false, "?"),
            new DosHeaderInfo("?", 0),
            new CoffHeaderInfo("?", 0, DateTime.MinValue, 0, 0, 0, "?"),
            null,
            Array.Empty<DataDirectoryInfo>(),
            Array.Empty<SectionInfo>(),
            Array.Empty<ImportedDll>(),
            Array.Empty<ExportedSymbol>(),
            null);

    private static DosHeaderInfo ReadDosHeader(byte[] bytes)
    {
        if (bytes.Length < 64) return new DosHeaderInfo("?", 0);
        var magic = Encoding.ASCII.GetString(bytes, 0, 2);
        var lfa = BitConverter.ToInt32(bytes, 60);
        return new DosHeaderInfo(magic, lfa);
    }

    private static CoffHeaderInfo BuildCoff(CoffHeader c) => new(
        Machine: c.Machine.ToString(),
        NumberOfSections: c.NumberOfSections,
        TimeDateStamp: DateTimeOffset.FromUnixTimeSeconds(unchecked((uint)c.TimeDateStamp)).UtcDateTime,
        PointerToSymbolTable: c.PointerToSymbolTable,
        NumberOfSymbols: c.NumberOfSymbols,
        SizeOfOptionalHeader: c.SizeOfOptionalHeader,
        Characteristics: c.Characteristics.ToString());

    private static OptionalHeaderInfo BuildOptional(PEHeader o) => new(
        Magic: o.Magic.ToString(),
        ImageBase: "0x" + o.ImageBase.ToString("X"),
        SizeOfImage: o.SizeOfImage,
        SizeOfHeaders: o.SizeOfHeaders,
        AddressOfEntryPoint: o.AddressOfEntryPoint,
        Subsystem: o.Subsystem.ToString(),
        SubsystemMajor: o.MajorSubsystemVersion,
        SubsystemMinor: o.MinorSubsystemVersion,
        DllCharacteristics: o.DllCharacteristics.ToString(),
        SectionAlignment: o.SectionAlignment,
        FileAlignment: o.FileAlignment,
        CheckSum: unchecked((int)o.CheckSum));

    private static IReadOnlyList<DataDirectoryInfo> BuildDataDirectories(PEHeader o)
    {
        var names = new[]
        {
            "Export Table", "Import Table", "Resource Table", "Exception Table",
            "Certificate Table", "Base Relocation Table", "Debug", "Architecture",
            "Global Ptr", "TLS Table", "Load Config Table", "Bound Import",
            "IAT", "Delay Import Descriptor", "CLR Runtime Header", "Reserved"
        };
        var dirs = new[]
        {
            o.ExportTableDirectory, o.ImportTableDirectory, o.ResourceTableDirectory, o.ExceptionTableDirectory,
            o.CertificateTableDirectory, o.BaseRelocationTableDirectory, o.DebugTableDirectory, o.CopyrightTableDirectory,
            o.GlobalPointerTableDirectory, o.ThreadLocalStorageTableDirectory, o.LoadConfigTableDirectory, o.BoundImportTableDirectory,
            o.ImportAddressTableDirectory, o.DelayImportTableDirectory, o.CorHeaderTableDirectory, default
        };
        return names.Zip(dirs, (n, d) => new DataDirectoryInfo(n, d.RelativeVirtualAddress, d.Size)).ToList();
    }

    private static IReadOnlyList<SectionInfo> BuildSections(IReadOnlyList<SectionHeader> headers)
    {
        var list = new List<SectionInfo>(headers.Count);
        foreach (var s in headers)
        {
            list.Add(new SectionInfo(
                Name: s.Name,
                VirtualAddress: s.VirtualAddress,
                VirtualSize: s.VirtualSize,
                RawSize: s.SizeOfRawData,
                RawPointer: s.PointerToRawData,
                Characteristics: s.SectionCharacteristics.ToString()));
        }
        return list;
    }

    private static IReadOnlyList<ImportedDll> TryReadImports(PEReader pe, PEHeader? opt)
    {
        if (opt is null) return Array.Empty<ImportedDll>();
        var dir = opt.ImportTableDirectory;
        if (dir.Size == 0) return Array.Empty<ImportedDll>();

        try
        {
            var section = pe.GetSectionData(dir.RelativeVirtualAddress);
            var reader = section.GetReader();
            var is64 = opt.Magic == PEMagic.PE32Plus;
            var result = new List<ImportedDll>();

            // IMAGE_IMPORT_DESCRIPTOR: 5 DWORDs (20 bytes), terminator is all zero
            while (reader.RemainingBytes >= 20)
            {
                int origFirstThunk = reader.ReadInt32();
                int timeDateStamp = reader.ReadInt32();
                int forwarderChain = reader.ReadInt32();
                int nameRva = reader.ReadInt32();
                int firstThunk = reader.ReadInt32();

                if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

                var dllName = ReadAsciiAt(pe, nameRva) ?? "<?>";
                var thunkRva = origFirstThunk != 0 ? origFirstThunk : firstThunk;
                var funcs = ReadThunks(pe, thunkRva, is64);
                result.Add(new ImportedDll(dllName, funcs));
            }
            return result;
        }
        catch
        {
            return Array.Empty<ImportedDll>();
        }
    }

    private static IReadOnlyList<ImportedFunction> ReadThunks(PEReader pe, int thunkRva, bool is64)
    {
        var list = new List<ImportedFunction>();
        if (thunkRva == 0) return list;
        try
        {
            var section = pe.GetSectionData(thunkRva);
            var reader = section.GetReader();
            int max = 4096; // safety cap
            while (max-- > 0 && reader.RemainingBytes >= (is64 ? 8 : 4))
            {
                long entry = is64 ? reader.ReadInt64() : reader.ReadInt32();
                if (entry == 0) break;

                var ordinalFlag = is64 ? unchecked((long)0x8000000000000000L) : 0x80000000L;
                if ((entry & ordinalFlag) != 0)
                {
                    int ord = (int)(entry & 0xFFFF);
                    list.Add(new ImportedFunction($"#{ord}", ord, true));
                }
                else
                {
                    int hintNameRva = (int)(entry & 0x7FFFFFFF);
                    var name = ReadHintName(pe, hintNameRva);
                    list.Add(new ImportedFunction(name ?? "<?>", 0, false));
                }
            }
        }
        catch
        {
            // best-effort
        }
        return list;
    }

    private static IReadOnlyList<ExportedSymbol> TryReadExports(PEReader pe, PEHeader? opt)
    {
        if (opt is null) return Array.Empty<ExportedSymbol>();
        var dir = opt.ExportTableDirectory;
        if (dir.Size == 0) return Array.Empty<ExportedSymbol>();

        try
        {
            var section = pe.GetSectionData(dir.RelativeVirtualAddress);
            var reader = section.GetReader();
            // IMAGE_EXPORT_DIRECTORY: skip first 16 bytes (Characteristics, Time, Major/Minor, Name)
            reader.ReadInt32();      // Characteristics
            reader.ReadInt32();      // TimeDateStamp
            reader.ReadInt16();      // MajorVersion
            reader.ReadInt16();      // MinorVersion
            reader.ReadInt32();      // Name (RVA)
            int ordBase = reader.ReadInt32();
            int numFuncs = reader.ReadInt32();
            int numNames = reader.ReadInt32();
            int funcsRva = reader.ReadInt32();
            int namesRva = reader.ReadInt32();
            int ordsRva = reader.ReadInt32();

            if (numFuncs <= 0 || numFuncs > 100_000) return Array.Empty<ExportedSymbol>();

            var funcRvas = ReadInt32Array(pe, funcsRva, numFuncs);
            var nameRvas = numNames > 0 ? ReadInt32Array(pe, namesRva, numNames) : Array.Empty<int>();
            var ordIndexes = numNames > 0 ? ReadUInt16Array(pe, ordsRva, numNames) : Array.Empty<ushort>();

            // Map function-index -> name (for those with names)
            var nameByIndex = new Dictionary<int, string>();
            for (int i = 0; i < numNames; i++)
            {
                int funcIndex = ordIndexes[i];
                var n = ReadAsciiAt(pe, nameRvas[i]);
                if (n is not null) nameByIndex[funcIndex] = n;
            }

            var result = new List<ExportedSymbol>(numFuncs);
            for (int i = 0; i < numFuncs; i++)
            {
                int rva = funcRvas[i];
                if (rva == 0) continue;
                var name = nameByIndex.TryGetValue(i, out var nm) ? nm : $"Ordinal_{ordBase + i}";

                // Forwarder if RVA points within the export directory
                string? forwarder = null;
                if (rva >= dir.RelativeVirtualAddress && rva < dir.RelativeVirtualAddress + dir.Size)
                {
                    forwarder = ReadAsciiAt(pe, rva);
                }
                result.Add(new ExportedSymbol(name, ordBase + i, rva, forwarder));
            }
            return result;
        }
        catch
        {
            return Array.Empty<ExportedSymbol>();
        }
    }

    private static int[] ReadInt32Array(PEReader pe, int rva, int count)
    {
        if (rva == 0 || count <= 0) return Array.Empty<int>();
        var section = pe.GetSectionData(rva);
        var reader = section.GetReader();
        var arr = new int[count];
        for (int i = 0; i < count; i++)
        {
            if (reader.RemainingBytes < 4) break;
            arr[i] = reader.ReadInt32();
        }
        return arr;
    }

    private static ushort[] ReadUInt16Array(PEReader pe, int rva, int count)
    {
        if (rva == 0 || count <= 0) return Array.Empty<ushort>();
        var section = pe.GetSectionData(rva);
        var reader = section.GetReader();
        var arr = new ushort[count];
        for (int i = 0; i < count; i++)
        {
            if (reader.RemainingBytes < 2) break;
            arr[i] = reader.ReadUInt16();
        }
        return arr;
    }

    private static string? ReadAsciiAt(PEReader pe, int rva)
    {
        if (rva == 0) return null;
        try
        {
            var section = pe.GetSectionData(rva);
            var reader = section.GetReader();
            var sb = new StringBuilder();
            while (reader.RemainingBytes > 0)
            {
                byte b = reader.ReadByte();
                if (b == 0) break;
                if (b < 32 || b > 126) return sb.ToString();
                sb.Append((char)b);
                if (sb.Length > 512) break;
            }
            return sb.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static string? ReadHintName(PEReader pe, int rva)
    {
        if (rva == 0) return null;
        try
        {
            var section = pe.GetSectionData(rva);
            var reader = section.GetReader();
            if (reader.RemainingBytes < 3) return null;
            reader.ReadUInt16(); // Hint
            var sb = new StringBuilder();
            while (reader.RemainingBytes > 0)
            {
                byte b = reader.ReadByte();
                if (b == 0) break;
                sb.Append((char)b);
                if (sb.Length > 512) break;
            }
            return sb.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static PESummary BuildSummary(CoffHeader coff, PEHeader? opt, PEReader pe, IReadOnlyList<SectionInfo> sections)
    {
        var arch = coff.Machine switch
        {
            Machine.Amd64 => "x64",
            Machine.I386 => "x86",
            Machine.Arm64 => "ARM64",
            Machine.Arm => "ARM",
            Machine.IA64 => "IA64",
            Machine.LoongArch64 => "LoongArch64",
            _ => coff.Machine.ToString()
        };

        var bits = opt?.Magic switch
        {
            PEMagic.PE32 => "32-bit",
            PEMagic.PE32Plus => "64-bit",
            _ => "?"
        };

        var subsystem = opt?.Subsystem switch
        {
            Subsystem.WindowsGui => "Windows GUI",
            Subsystem.WindowsCui => "Windows Console",
            Subsystem.Native => "Native (driver)",
            Subsystem.EfiApplication => "EFI Application",
            Subsystem.EfiBootServiceDriver => "EFI Boot Service Driver",
            Subsystem.EfiRuntimeDriver => "EFI Runtime Driver",
            _ => opt?.Subsystem.ToString() ?? "Unknown"
        };

        var isDll = (coff.Characteristics & Characteristics.Dll) != 0;
        var isSystem = (coff.Characteristics & Characteristics.System) != 0;
        var type = isDll ? "DLL" : isSystem ? "System File" : "Executable";

        var dll = opt?.DllCharacteristics ?? 0;
        bool aslr = (dll & DllCharacteristics.DynamicBase) != 0;
        bool dep = (dll & DllCharacteristics.NxCompatible) != 0;
        bool cfg = (dll & DllCharacteristics.ControlFlowGuard) != 0;
        bool highEntropy = (dll & DllCharacteristics.HighEntropyVirtualAddressSpace) != 0;
        bool tsAware = (dll & DllCharacteristics.TerminalServerAware) != 0;

        bool managed = pe.HasMetadata;
        bool signed = (opt?.CertificateTableDirectory.Size ?? 0) > 0;

        var ts = DateTimeOffset.FromUnixTimeSeconds(unchecked((uint)coff.TimeDateStamp)).UtcDateTime;

        return new PESummary(arch, subsystem, type, ts, managed, signed, aslr, dep, cfg, highEntropy, tsAware, bits);
    }
}
