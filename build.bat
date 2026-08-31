@echo off
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /platform:anycpu /win32manifest:app.manifest /win32icon:app.ico /out:USBController.exe /r:System.Windows.Forms.dll,System.Drawing.dll,System.dll USBController.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:winexe /platform:anycpu /win32manifest:app.manifest /win32icon:app.ico /out:Setup.exe /r:System.Windows.Forms.dll,System.Drawing.dll,System.dll,Microsoft.CSharp.dll Setup.cs
echo Build complete! USBController.exe and Setup.exe are ready.
pause
