;; IsDebuggerPresent Tool
;;
;; It's an antidebugger tool for learning reverse engineering stuff.
;; I think this protection is a bit more advanced than basic IsDebuggerPresent check
;; Just attach a debugger and it will flag you. Whoever bypasses it is advanced at hacking in my opinion.
;;
;; Github: https://github.com/kevinalberts
;; Discord: Girexo#1974

#RequireAdmin
#Include <Console.au3>
#Include <NtProcess.au3>
#Include <String.au3>
#Include <WinAPI.au3>

$iRedFlag = 0
$CurrentProcessName = _WinAPI_ProcessGetFilename(@AutoItPID,False)
$dwHandle = OpenProcess(0x1F0FFF, 0, ProcessExists($CurrentProcessName))
$dwBaseAddress = _MemoryModuleGetBaseAddress(ProcessExists($CurrentProcessName),$CurrentProcessName)
Local $hModule = _WinAPI_GetModuleHandle("kernelbase.dll")
$rAddy_ = _WinAPI_GetProcAddress($hModule, "IsDebuggerPresent")
$rAddy_SavedBytes = NtReadVirtualMemory($dwHandle, $rAddy_, "byte[16]")
Cout("")
AdlibRegister("IsDebuggerPresent",1)
AdlibRegister("MemoryDetection",1)
AdlibRegister("RedFlag",1)

While 1
	Sleep(10)
WEnd


Func IsDebuggerPresent()
	$hRet = DLLCall(DLLOpen('Kernel32.dll'), 'Int', 'IsDebuggerPresent')[0]
	If $hRet > 0 Then
		$iRedFlag = 1
	EndIf
EndFunc

Func MemoryDetection()
	If NtReadVirtualMemory($dwHandle, $rAddy_, "byte[16]") <> $rAddy_SavedBytes Then
		$iRedFlag = 1
	EndIf
EndFunc

Func _WinAPI_ProcessGetFilename($vProcessID, $bFullPath = False) ;;Got it from someone on autoit forums idk who.
    ; Not a Process ID? Must be a Process Name
    If Not IsNumber($vProcessID) Then
        $vProcessID = ProcessExists($vProcessID)
        ; Process Name not found (or invalid parameter?)
        If $vProcessID == 0 Then Return SetError(1, 0, "")
    EndIf

    Local $hProcess, $stFilename, $aRet, $sFilename, $sDLLFunctionName

    ; Since the parameters and returns are the same for both of these DLL calls, we can keep it all in one function
    If $bFullPath Then
        $sDLLFunctionName = "GetModuleFileNameEx"
    Else
        $sDLLFunctionName = "GetModuleBaseName"
    EndIf

    ; Get process handle (lod3n)
    Local $hProcess = DllCall('kernel32.dll', 'ptr', 'OpenProcess', 'int', BitOR(0x400, 0x10), 'int', 0, 'int', $vProcessID)
    If @error Or Not IsArray($hProcess) Then Return SetError(2, 0, "")

    ; Create 'receiving' string buffers and make the call
    ;If @AutoItUnicode Then
    ; Path length size maximum in Unicode is 32767 (-1 for NULL)
    $stFilename = DllStructCreate("wchar[32767]")
    ; we append 'W' to function names because these are the 'Wide' (Unicode) variants
    $aRet = DllCall("Psapi.dll", "dword", $sDLLFunctionName & 'W', _
            "ptr", $hProcess[0], "ptr", Chr(0), "ptr", DllStructGetPtr($stFilename), "dword", 32767)
    ;Else
    #cs
        ; Path length size maximum otherwise is 260 (-1 for NULL)
        $stFilename=DllStructCreate("char[260]")
        $aRet=DllCall("Psapi.dll","dword",$sDLLFunctionName, _
        "ptr",$hProcess[0],"ptr",Chr(0),"ptr",DllStructGetPtr($stFilename),"dword",260)
        EndIf
    #ce

    ; Error from either call? Cleanup and exit with error
    If @error Or Not IsArray($aRet) Then
        ; Close the process handle
        DllCall('kernel32.dll', 'ptr', 'CloseHandle', 'ptr', $hProcess[0])
        ; DLLStructDelete()'s:
        $stFilename = 0
        $hProcess = 0
        Return SetError(2, 0, "")
    EndIf

    ;$aRet[0] = size of string copied over, minus null-terminator
    ;$stFilename should now contain either the filename or full path string (based on $bFullPath)
    $sFilename = DllStructGetData($stFilename, 1)

    DllCall('kernel32.dll', 'ptr', 'CloseHandle', 'ptr', $hProcess[0])
    ; DLLStructDelete()'s
    $stFilename = 0
    $hProcess = 0

    Return SetError(0, 0, $sFilename)
EndFunc   ;==>_WinAPI_ProcessGetFilename

Func RedFlag()
If $iRedFlag = 1 Then
	AdlibUnRegister("IsDebuggerPresent")
	AdlibUnRegister("MemoryDetection")
	Cout("IsDebuggerPresent detected! Closing application...")
	Sleep(2000)
	Exit
EndIf
EndFunc