# Fixed, internal IMAPI2FS/IStream adapter. Source files are data only.
# Invoked by the W1 job runner in its fresh private working directory.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($args.Count -ne 0) { throw 'This adapter takes no command arguments.' }
if (-not [Environment]::Is64BitProcess) { throw 'Native amd64 PowerShell required.' }
if ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'This probe requires a non-elevated token.' }

Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class P1ISOStream {
    [DllImport("shlwapi.dll", CharSet=CharSet.Unicode, PreserveSig=false)]
    private static extern void SHCreateStreamOnFileEx(string path, uint mode,
        uint attributes, [MarshalAs(UnmanagedType.Bool)] bool create,
        IntPtr template, out IStream stream);
    public static object OpenBoot(string path) {
        IStream stream;
        // STGM_READ | STGM_SHARE_DENY_WRITE. Go also holds deny-delete handles.
        SHCreateStreamOnFileEx(path, 0x20, 0x80, false, IntPtr.Zero, out stream);
        return stream;
    }
    public static long Save(object source, string path, long expected) {
        if (expected <= 0 || expected > 2147483648L || expected % 2048 != 0)
            throw new InvalidDataException("Invalid bounded result stream length.");
        IStream input = (IStream)source;
        byte[] buffer = new byte[1048576];
        IntPtr count = Marshal.AllocCoTaskMem(4);
        try {
            using (FileStream output = new FileStream(path, FileMode.CreateNew,
                    FileAccess.Write, FileShare.None, buffer.Length)) {
                long written = 0;
                while (written < expected) {
                    int request = (int)Math.Min(buffer.Length, expected-written);
                    Marshal.WriteInt32(count, 0);
                    input.Read(buffer, request, count);
                    int got = Marshal.ReadInt32(count);
                    if (got <= 0 || got > request)
                        throw new InvalidDataException("Short/invalid IStream read.");
                    output.Write(buffer, 0, got);
                    written += got;
                }
                Marshal.WriteInt32(count, 0);
                input.Read(buffer, 1, count);
                if (Marshal.ReadInt32(count) != 0)
                    throw new InvalidDataException("IStream exceeded declared length.");
                output.Flush(true);
                return written;
            }
        } finally { Marshal.FreeCoTaskMem(count); }
    }
}
'@

# The native COM producer rejects extended-prefix paths. The caller verified
# this ordinary absolute script path against the held rooted file identity.
$workspace = [IO.Directory]::GetParent($PSScriptRoot).FullName
if ($workspace -notmatch '^[A-Za-z]:\\' -or $workspace.Length -gt 220 -or $workspace.Contains('..')) { throw 'A bounded ordinary local workspace path is required.' }
$tree = [IO.Path]::Combine($workspace, 'media')
$bootPath = [IO.Path]::Combine($workspace, 'media\EFI\MICROSOFT\BOOT\EFISYS.BIN')
$image = $null
$boot = $null
$bootStream = $null
$result = $null
$imageStream = $null
try {
    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $image.WorkingDirectory = [IO.Path]::Combine($workspace, 'scratch')
    $image.SessionStartBlock = 0
    $image.FreeMediaBlocks = 0
    $image.FileSystemsToCreate = 5
    $image.UDFRevision = 0x102
    $image.ISO9660InterchangeLevel = 2
    $image.VolumeName = 'P1AMD64'
    $image.StageFiles = $false
    $image.StrictFileSystemCompliance = $true
    $image.UseRestrictedCharacterSet = $true
    $image.Root.AddTree($tree, $false)
    if ($image.FileCount -ne 5) { throw 'Expected exactly 5 staged files.' }
    $bootStream = [P1ISOStream]::OpenBoot($bootPath)
    $boot = New-Object -ComObject IMAPI2FS.BootOptions
    $boot.AssignBootImage($bootStream)
    $boot.Emulation = 0
    $boot.PlatformId = 0xef
    $boot.Manufacturer = 'P1 amd64 source data'
    if ($boot.ImageSize -ne 1474560 -or $boot.Emulation -ne 0 -or $boot.PlatformId -ne 0xef) { throw 'Boot option read-back differs.' }
    $image.BootImageOptions = $boot
    if ($image.FileSystemsToCreate -ne 5 -or $image.UDFRevision -ne 0x102 -or $image.SessionStartBlock -ne 0 -or $image.FreeMediaBlocks -ne 0) { throw 'Native recipe read-back differs.' }
    $result = $image.CreateResultImage()
    if ($result.BlockSize -ne 2048) { throw 'Unexpected native result block size.' }
    $imageStream = $result.ImageStream
    $bytes = [P1ISOStream]::Save($imageStream, [IO.Path]::Combine($workspace, 'outputs\p1-amd64-source-capsule.iso'), ([long]$result.BlockSize * [long]$result.TotalBlocks))
    $receipt = [ordered]@{
        schema = 1; recipe = 'p1-amd64-source-capsule-v1'; fileSystems = [int]$image.FileSystemsToCreate
        udfRevision = [int]$image.UDFRevision; volume = [string]$image.VolumeName
        sessionStartBlock = [int]$image.SessionStartBlock; freeMediaBlocks = [int]$image.FreeMediaBlocks
        fileCount = [int]$image.FileCount; directoryCount = [int]$image.DirectoryCount
        bootPlatform = [int]$boot.PlatformId; bootEmulation = [int]$boot.Emulation; bootBytes = [long]$boot.ImageSize
        blockSize = [int]$result.BlockSize; totalBlocks = [long]$result.TotalBlocks; bytes = $bytes
        classification = 'source-capsule; full Windows Setup/boot and servicing unverified'
    }
    $json = $receipt | ConvertTo-Json -Depth 4
    [IO.File]::WriteAllText([IO.Path]::Combine($workspace, 'logs\native-result.json'), $json, [Text.UTF8Encoding]::new($false))
    $json
} finally {
    foreach ($obj in @($imageStream, $result, $boot, $bootStream, $image)) {
        if ($null -ne $obj -and [Runtime.InteropServices.Marshal]::IsComObject($obj)) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($obj) }
    }
}
