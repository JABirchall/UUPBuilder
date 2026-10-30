# Fixed, internal IMAPI2FS/IStream adapter. Source files are data only.
# Invoked by the W1 job runner in its fresh private working directory.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($args.Count -ne 0) { throw 'This adapter takes no command arguments.' }



Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public static class UUPISOStream {
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
        if (expected <= 0 || expected > 137438953472L || expected % 2048 != 0)
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

$request = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'master.json') | ConvertFrom-Json
$image = $null
$result = $null
$imageStream = $null
$objects = @()
try {
    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
    $image.WorkingDirectory = $request.scratch
    $image.SessionStartBlock = 0
    $image.FreeMediaBlocks = 0
    $image.FileSystemsToCreate = 4
    $image.UDFRevision = 0x102
    $image.VolumeName = $request.label
    $image.StageFiles = $false
    $image.StrictFileSystemCompliance = $true
    $image.UseRestrictedCharacterSet = $false
    $image.Root.AddTree($request.media, $false)
    if ($image.FileCount -ne $request.files) { throw 'Staged media file count changed.' }
    $options = @()
    foreach ($entry in $request.boot) {
        $stream = [UUPISOStream]::OpenBoot($entry.path)
        $boot = New-Object -ComObject IMAPI2FS.BootOptions
        $boot.AssignBootImage($stream)
        $boot.Emulation = 0
        $boot.PlatformId = [int]$entry.platform
        $boot.Manufacturer = 'Microsoft Windows'
        $options += $boot
        $objects += $boot
        $objects += $stream
    }
    # Array.SetValue unwraps PowerShell's PSObject wrapper before COM marshaling.
    $dispatch = [array]::CreateInstance([object], $options.Count)
    for ($i = 0; $i -lt $options.Count; $i++) { $dispatch.SetValue($options[$i], $i) }
    $image.BootImageOptionsArray = $dispatch
    $result = $image.CreateResultImage()
    if ($result.BlockSize -ne 2048) { throw 'Unexpected native result block size.' }
    $imageStream = $result.ImageStream
    [void][UUPISOStream]::Save($imageStream, $request.output, ([long]$result.BlockSize * [long]$result.TotalBlocks))
} finally {
    foreach ($obj in (@($imageStream, $result) + $objects + @($image))) {
        if ($null -ne $obj -and [Runtime.InteropServices.Marshal]::IsComObject($obj)) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($obj) }
    }
}
