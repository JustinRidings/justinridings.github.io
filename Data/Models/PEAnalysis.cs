namespace PersonalSite.Data.Models;

public sealed record PEAnalysis(
    string FileName,
    long FileSize,
    bool IsValid,
    string? Error,
    PESummary Summary,
    DosHeaderInfo Dos,
    CoffHeaderInfo Coff,
    OptionalHeaderInfo? Optional,
    IReadOnlyList<DataDirectoryInfo> DataDirectories,
    IReadOnlyList<SectionInfo> Sections,
    IReadOnlyList<ImportedDll> Imports,
    IReadOnlyList<ExportedSymbol> Exports,
    ClrHeaderInfo? Clr);

public sealed record PESummary(
    string Architecture,
    string Subsystem,
    string Type,
    DateTime LinkerTimestamp,
    bool IsManaged,
    bool IsSigned,
    bool HasAslr,
    bool HasDep,
    bool HasCfg,
    bool IsHighEntropyVa,
    bool IsTerminalServerAware,
    string Bits);

public sealed record DosHeaderInfo(string Magic, int LfaNew);

public sealed record CoffHeaderInfo(
    string Machine,
    int NumberOfSections,
    DateTime TimeDateStamp,
    int PointerToSymbolTable,
    int NumberOfSymbols,
    int SizeOfOptionalHeader,
    string Characteristics);

public sealed record OptionalHeaderInfo(
    string Magic,
    string ImageBase,
    int SizeOfImage,
    int SizeOfHeaders,
    int AddressOfEntryPoint,
    string Subsystem,
    int SubsystemMajor,
    int SubsystemMinor,
    string DllCharacteristics,
    int SectionAlignment,
    int FileAlignment,
    int CheckSum);

public sealed record DataDirectoryInfo(string Name, int RVA, int Size);

public sealed record SectionInfo(
    string Name,
    int VirtualAddress,
    int VirtualSize,
    int RawSize,
    int RawPointer,
    string Characteristics);

public sealed record ImportedDll(string Name, IReadOnlyList<ImportedFunction> Functions);

public sealed record ImportedFunction(string Name, int Ordinal, bool IsByOrdinal);

public sealed record ExportedSymbol(string Name, int Ordinal, int RVA, string? ForwarderName);

public sealed record ClrHeaderInfo(
    int MajorRuntimeVersion,
    int MinorRuntimeVersion,
    int MetadataRVA,
    int MetadataSize,
    string Flags,
    int EntryPointToken);
