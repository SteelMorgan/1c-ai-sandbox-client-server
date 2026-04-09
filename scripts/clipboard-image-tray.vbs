Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "powershell -ExecutionPolicy Bypass -File """ & Replace(WScript.ScriptFullName, "clipboard-image-tray.vbs", "clipboard-image-tray.ps1") & """", 0, False
