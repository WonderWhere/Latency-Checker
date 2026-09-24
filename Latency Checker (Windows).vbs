' Double-click to open the Latency Checker viewer on Windows with no console window.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir
If Not fso.FileExists(dir & "\.venv\Scripts\pythonw.exe") Then
  If sh.Run("cmd /c py -3 -m venv .venv", 0, True) <> 0 Then
    MsgBox "Python 3 is required: https://www.python.org/downloads/", 16, "Latency Checker"
    WScript.Quit 1
  End If
End If
sh.Run "cmd /c .venv\Scripts\pip install -q --disable-pip-version-check -r requirements.txt", 0, True
sh.Run """" & dir & "\.venv\Scripts\pythonw.exe"" latency_viewer.py", 0, False
