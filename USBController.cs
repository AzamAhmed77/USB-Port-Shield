using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using System.Security.Principal;
using System.Diagnostics;
using System.Threading;
using Microsoft.Win32;

namespace USBPortControllerApp
{
    public enum AppLanguage
    {
        Arabic,
        English
    }

    #region Security Activity Logger
    public static class SecurityLogger
    {
        private static readonly string LogFilePath;

        static SecurityLogger()
        {
            try
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "USBPortControllerShield");
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                LogFilePath = Path.Combine(dir, "security_events.log");
            }
            catch
            {
                LogFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "security_events.log");
            }
        }

        public static void LogEvent(string eventType, string details)
        {
            try
            {
                string line = string.Format("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}", DateTime.Now, eventType, details);
                File.AppendAllText(LogFilePath, line + Environment.NewLine, Encoding.UTF8);
            }
            catch { }
        }

        public static string[] ReadRecentLogs(int maxLines = 100)
        {
            try
            {
                if (File.Exists(LogFilePath))
                {
                    string[] lines = File.ReadAllLines(LogFilePath, Encoding.UTF8);
                    if (lines.Length <= maxLines) return lines;
                    string[] recent = new string[maxLines];
                    Array.Copy(lines, lines.Length - maxLines, recent, 0, maxLines);
                    return recent;
                }
            }
            catch { }
            return new string[0];
        }

        public static void ClearLogs()
        {
            try
            {
                if (File.Exists(LogFilePath)) File.Delete(LogFilePath);
                LogEvent("LOGS_CLEARED", Loc.T("تم مسح السجلات الأمنية بواسطة المسؤول", "Security logs cleared by Administrator"));
            }
            catch { }
        }

        public static string GetLogPath()
        {
            return LogFilePath;
        }
    }
    #endregion

    #region USB Hardware & PnP Controller Manager
    public class UsbDeviceInfo
    {
        public string InstanceId { get; set; }
        public string Description { get; set; }
        public string SerialNumber { get; set; }
        public string Status { get; set; }
        public string DriveLetter { get; set; }
        public string DisplayName { get; set; }
    }

    public static class UsbHardwareManager
    {
        // 100% In-Memory Fast Detection (0ms lag, no process spawning on UI thread)
        public static List<UsbDeviceInfo> GetActiveUsbStorageDevices()
        {
            List<UsbDeviceInfo> list = new List<UsbDeviceInfo>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Scan mounted removable drives via DriveInfo
            try
            {
                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (d.DriveType == DriveType.Removable && d.IsReady)
                        {
                            string label = string.IsNullOrEmpty(d.VolumeLabel) ? Loc.T("فلاشة USB", "USB Flash Drive") : d.VolumeLabel;
                            double sizeGb = Math.Round((double)d.TotalSize / (1024 * 1024 * 1024), 1);
                            string letter = d.Name.TrimEnd('\\');
                            string display = string.Format("🔌 {0} ({1}) - {2} GB", label, letter, sizeGb);

                            seen.Add(letter);
                            list.Add(new UsbDeviceInfo
                            {
                                InstanceId = letter,
                                Description = label,
                                DriveLetter = letter,
                                DisplayName = display,
                                Status = "Started"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            // 2. Scan Registry for attached USB storage devices (fast in-memory registry read)
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR"))
                {
                    if (key != null)
                    {
                        foreach (string subKeyName in key.GetSubKeyNames())
                        {
                            using (RegistryKey subKey = key.OpenSubKey(subKeyName))
                            {
                                if (subKey != null)
                                {
                                    foreach (string serial in subKey.GetSubKeyNames())
                                    {
                                        using (RegistryKey serialKey = subKey.OpenSubKey(serial))
                                        {
                                            if (serialKey != null)
                                            {
                                                string friendlyName = serialKey.GetValue("FriendlyName") as string;
                                                string cleanName = !string.IsNullOrEmpty(friendlyName)
                                                    ? friendlyName
                                                    : subKeyName.Replace("Disk&Ven_", "").Replace("&Prod_", " ").Replace("&Rev_", " ");
                                                
                                                string shortSerial = serial.Length > 8 ? serial.Substring(0, 8) : serial;
                                                string display = string.Format("🔌 {0} ({1})", cleanName, shortSerial);

                                                if (!seen.Contains(display) && !seen.Contains(cleanName))
                                                {
                                                    seen.Add(display);
                                                    list.Add(new UsbDeviceInfo
                                                    {
                                                        InstanceId = string.Format(@"USBSTOR\{0}\{1}", subKeyName, serial),
                                                        Description = cleanName,
                                                        SerialNumber = serial,
                                                        DisplayName = display,
                                                        Status = "Started"
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            return list;
        }

        public static void DisableAllUsbStorage()
        {
            // 1. Set USBSTOR Start = 4 in Registry
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 4, RegistryValueKind.DWord);
                    }
                }
            }
            catch { }

            // 2. In background thread, dismount mounted removable volumes so they disappear immediately
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    foreach (DriveInfo d in DriveInfo.GetDrives())
                    {
                        if (d.DriveType == DriveType.Removable)
                        {
                            string letter = d.Name.TrimEnd('\\');
                            try
                            {
                                ProcessStartInfo psi = new ProcessStartInfo("mountvol.exe", string.Format("{0}: /p", letter))
                                {
                                    CreateNoWindow = true,
                                    UseShellExecute = false,
                                    WindowStyle = ProcessWindowStyle.Hidden
                                };
                                using (Process p = Process.Start(psi))
                                {
                                    if (p != null) p.WaitForExit(1000);
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            });
        }

        public static void EnableAllUsbStorage()
        {
            // 1. Set USBSTOR Start = 3 in Registry
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 3, RegistryValueKind.DWord);
                    }
                }
            }
            catch { }

            // 2. In background: Re-enable automount, repair any disabled PnP nodes, and rescan
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    // Enable Automount
                    ProcessStartInfo psiMount = new ProcessStartInfo("mountvol.exe", "/e")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };
                    using (Process p = Process.Start(psiMount))
                    {
                        if (p != null) p.WaitForExit(1000);
                    }

                    // Repair any disabled USBSTOR devices from previous sessions
                    RepairDisabledUsbDevices();

                    // Rescan devices
                    ProcessStartInfo psi = new ProcessStartInfo("pnputil.exe", "/scan-devices")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden
                    };
                    using (Process p = Process.Start(psi))
                    {
                        if (p != null) p.WaitForExit(3000);
                    }
                }
                catch { }
            });
        }

        public static void RepairDisabledUsbDevices()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("pnputil.exe", "/enum-devices /problem")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using (Process p = Process.Start(psi))
                {
                    if (p != null)
                    {
                        string output = p.StandardOutput.ReadToEnd();
                        p.WaitForExit(3000);
                        if (!string.IsNullOrEmpty(output))
                        {
                            string[] lines = output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (string line in lines)
                            {
                                string trim = line.Trim();
                                if (trim.StartsWith("Instance ID:", StringComparison.OrdinalIgnoreCase))
                                {
                                    string id = trim.Substring("Instance ID:".Length).Trim();
                                    if (id.IndexOf("USBSTOR", StringComparison.OrdinalIgnoreCase) >= 0 || id.IndexOf("USB", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        EnableDeviceNode(id);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private static void EnableDeviceNode(string instanceId)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo("pnputil.exe", string.Format("/enable-device \"{0}\"", instanceId))
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    WindowStyle = ProcessWindowStyle.Hidden
                };
                using (Process p = Process.Start(psi))
                {
                    if (p != null) p.WaitForExit(2000);
                }
            }
            catch { }
        }

        public static void EnforceWhitelist()
        {
            if (!WhitelistManager.IsWhitelistModeEnabled()) return;

            var whitelisted = WhitelistManager.GetWhitelistedDevices();
            var connected = GetActiveUsbStorageDevices();

            // When whitelist mode has authorized devices, keep USBSTOR enabled
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", 3, RegistryValueKind.DWord);
                    }
                }
            }
            catch { }

            // Dismount any removable drive that does not match whitelist
            foreach (var dev in connected)
            {
                bool authorized = false;
                foreach (var w in whitelisted)
                {
                    if (dev.InstanceId.IndexOf(w.DeviceId, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        w.DeviceId.IndexOf(dev.InstanceId, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        dev.Description.IndexOf(w.Name, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        w.Name.IndexOf(dev.Description, StringComparison.OrdinalIgnoreCase) >= 0 ||
                        (!string.IsNullOrEmpty(dev.SerialNumber) && dev.SerialNumber.IndexOf(w.DeviceId, StringComparison.OrdinalIgnoreCase) >= 0) ||
                        (!string.IsNullOrEmpty(dev.SerialNumber) && w.DeviceId.IndexOf(dev.SerialNumber, StringComparison.OrdinalIgnoreCase) >= 0) ||
                        (!string.IsNullOrEmpty(dev.DisplayName) && dev.DisplayName.IndexOf(w.Name, StringComparison.OrdinalIgnoreCase) >= 0) ||
                        (!string.IsNullOrEmpty(dev.DisplayName) && w.Name.IndexOf(dev.DisplayName, StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        authorized = true;
                        break;
                    }
                }

                if (!authorized && !string.IsNullOrEmpty(dev.DriveLetter))
                {
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo("mountvol.exe", string.Format("{0}: /p", dev.DriveLetter))
                        {
                            CreateNoWindow = true,
                            UseShellExecute = false,
                            WindowStyle = ProcessWindowStyle.Hidden
                        };
                        using (Process p = Process.Start(psi))
                        {
                            if (p != null) p.WaitForExit(1000);
                        }
                    }
                    catch { }
                }
            }
        }
    }
    #endregion

    #region USB Whitelist Manager
    public class WhitelistDevice
    {
        public string DeviceId { get; set; }
        public string Name { get; set; }
        public string AddedDate { get; set; }
    }

    public static class WhitelistManager
    {
        private const string RegKeyPath = @"Software\USBPortController\Whitelist";
        private const string EnabledValue = "WhitelistEnabled";

        public static bool IsWhitelistModeEnabled()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegKeyPath))
                {
                    if (key != null)
                    {
                        object val = key.GetValue(EnabledValue);
                        if (val != null) return Convert.ToInt32(val) == 1;
                    }
                }
            }
            catch { }
            return false;
        }

        public static void SetWhitelistModeEnabled(bool enable)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RegKeyPath))
                {
                    if (key != null)
                    {
                        key.SetValue(EnabledValue, enable ? 1 : 0, RegistryValueKind.DWord);
                    }
                }
            }
            catch { }
        }

        public static List<string> GetConnectedUsbDrives()
        {
            List<string> drives = new List<string>();
            try
            {
                var devices = UsbHardwareManager.GetActiveUsbStorageDevices();
                foreach (var dev in devices)
                {
                    drives.Add(dev.DisplayName ?? dev.Description);
                }
            }
            catch { }
            return drives;
        }

        public static List<WhitelistDevice> GetWhitelistedDevices()
        {
            List<WhitelistDevice> list = new List<WhitelistDevice>();
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegKeyPath + @"\Devices"))
                {
                    if (key != null)
                    {
                        foreach (string name in key.GetValueNames())
                        {
                            string data = key.GetValue(name) as string ?? "";
                            string[] parts = data.Split('|');
                            list.Add(new WhitelistDevice
                            {
                                DeviceId = name,
                                Name = parts.Length > 0 ? parts[0] : name,
                                AddedDate = parts.Length > 1 ? parts[1] : DateTime.Now.ToString("yyyy-MM-dd")
                            });
                        }
                    }
                }
            }
            catch { }
            return list;
        }

        public static void AddDevice(string deviceId, string deviceName)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RegKeyPath + @"\Devices"))
                {
                    if (key != null)
                    {
                        string data = string.Format("{0}|{1:yyyy-MM-dd HH:mm}", deviceName, DateTime.Now);
                        key.SetValue(deviceId.Trim(), data, RegistryValueKind.String);
                        SecurityLogger.LogEvent("WHITELIST_DEVICE_ADDED", Loc.T("تمت إضافة جهاز مصرح به للقائمة البيضاء: " + deviceName, "Authorized device added to whitelist: " + deviceName));
                    }
                }
            }
            catch { }
        }

        public static void RemoveDevice(string deviceId)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RegKeyPath + @"\Devices"))
                {
                    if (key != null)
                    {
                        key.DeleteValue(deviceId, false);
                        SecurityLogger.LogEvent("WHITELIST_DEVICE_REMOVED", Loc.T("تم حذف جهاز من القائمة البيضاء: " + deviceId, "Device removed from whitelist: " + deviceId));
                    }
                }
            }
            catch { }
        }

        public static bool IsDeviceAuthorized(string deviceId)
        {
            if (!IsWhitelistModeEnabled()) return true;
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegKeyPath + @"\Devices"))
                {
                    if (key != null)
                    {
                        foreach (string name in key.GetValueNames())
                        {
                            if (deviceId.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0 || name.IndexOf(deviceId, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch { }
            return false;
        }
    }
    #endregion

    #region Localization Manager
    public static class Loc
    {
        private const string RegKeyPath = @"Software\USBPortController\Settings";
        private const string LangValueName = "Language";

        private static AppLanguage _currentLanguage = AppLanguage.Arabic;
        public static AppLanguage CurrentLanguage
        {
            get { return _currentLanguage; }
            set { _currentLanguage = value; }
        }

        static Loc()
        {
            LoadLanguage();
        }

        public static void LoadLanguage()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegKeyPath))
                {
                    if (key != null)
                    {
                        string lang = key.GetValue(LangValueName) as string;
                        if (!string.IsNullOrEmpty(lang) && lang.Equals("English", StringComparison.OrdinalIgnoreCase))
                        {
                            CurrentLanguage = AppLanguage.English;
                            return;
                        }
                    }
                }
            }
            catch { }
            CurrentLanguage = AppLanguage.Arabic;
        }

        public static void SetLanguage(AppLanguage lang)
        {
            CurrentLanguage = lang;
            try
            {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RegKeyPath))
                {
                    if (key != null)
                    {
                        key.SetValue(LangValueName, lang.ToString(), RegistryValueKind.String);
                    }
                }
            }
            catch { }
        }

        public static bool IsArabic
        {
            get { return CurrentLanguage == AppLanguage.Arabic; }
        }

        public static string T(string ar, string en)
        {
            return IsArabic ? ar : en;
        }
    }
    #endregion

    #region Auto-Lock Timer Manager
    public static class AutoLockTimerManager
    {
        private static System.Windows.Forms.Timer countdownTimer;
        private static int remainingSeconds = 0;
        public static Action<int> OnTick;
        public static Action OnExpired;

        public static bool IsTimerRunning
        {
            get { return remainingSeconds > 0; }
        }

        public static int RemainingSeconds
        {
            get { return remainingSeconds; }
        }

        public static void StartTimer(int minutes, Action onExpiredCallback)
        {
            StopTimer();
            remainingSeconds = minutes * 60;
            OnExpired = onExpiredCallback;

            countdownTimer = new System.Windows.Forms.Timer();
            countdownTimer.Interval = 1000;
            countdownTimer.Tick += (s, e) =>
            {
                remainingSeconds--;
                if (OnTick != null) OnTick(remainingSeconds);

                if (remainingSeconds <= 0)
                {
                    StopTimer();
                    if (OnExpired != null) OnExpired();
                }
            };
            countdownTimer.Start();
            SecurityLogger.LogEvent("TIMER_STARTED", Loc.T("تم تفعيل مؤقت الفتح المؤقت لمدة " + minutes + " دقيقة", "Temporary unlock timer started for " + minutes + " mins"));
        }

        public static void StopTimer()
        {
            if (countdownTimer != null)
            {
                countdownTimer.Stop();
                countdownTimer.Dispose();
                countdownTimer = null;
            }
            remainingSeconds = 0;
        }
    }
    #endregion

    #region Webhook & Telegram Alerts & Remote Control Manager
    public static class AlertNotifier
    {
        private const string RegKeyPath = @"Software\USBPortController\Alerts";
        private static Thread pollingThread = null;
        private static bool isPolling = false;
        private static long lastUpdateId = 0;

        // Callbacks for Remote Commands
        public static Func<bool> GetUsbStorageStateFunc;
        public static Action<bool> SetUsbStorageStateFunc;
        public static Func<bool> GetWriteProtectStateFunc;
        public static Action<bool> SetWriteProtectStateFunc;
        public static Action<int> StartAutoLockTimerFunc;

        public static string GetDeviceFingerprint()
        {
            try
            {
                string hostName = Dns.GetHostName();
                string ipAddress = "127.0.0.1";
                try
                {
                    IPHostEntry entry = Dns.GetHostEntry(hostName);
                    foreach (IPAddress ip in entry.AddressList)
                    {
                        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                        {
                            ipAddress = ip.ToString();
                            break;
                        }
                    }
                }
                catch { }

                return string.Format("🖥️ Device: {0} | 👤 User: {1} | 🌐 IP: {2}", Environment.MachineName, Environment.UserName, ipAddress);
            }
            catch
            {
                return string.Format("🖥️ Device: {0}", Environment.MachineName);
            }
        }

        public static void SendTelegramAlert(string botToken, string chatId, string message, bool appendFingerprint = true)
        {
            if (string.IsNullOrEmpty(botToken) || string.IsNullOrEmpty(chatId)) return;
            new Thread(() =>
            {
                try
                {
                    ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
                    string fullMessage = message;
                    if (appendFingerprint)
                    {
                        fullMessage = string.Format("{0}\n\n📌 {1}", message, GetDeviceFingerprint());
                    }

                    string url = string.Format("https://api.telegram.org/bot{0}/sendMessage?chat_id={1}&text={2}",
                        Uri.EscapeDataString(botToken),
                        Uri.EscapeDataString(chatId),
                        Uri.EscapeDataString(fullMessage));
                    using (WebClient client = new WebClient())
                    {
                        client.Encoding = Encoding.UTF8;
                        client.DownloadString(url);
                    }
                }
                catch { }
            }).Start();
        }

        public static void StartRemoteControlListener()
        {
            if (isPolling) return;
            isPolling = true;

            pollingThread = new Thread(() =>
            {
                while (isPolling)
                {
                    try
                    {
                        string botToken, configuredChatId;
                        LoadTelegramConfig(out botToken, out configuredChatId);

                        if (!string.IsNullOrEmpty(botToken) && !string.IsNullOrEmpty(configuredChatId))
                        {
                            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072 | SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
                            string url = string.Format("https://api.telegram.org/bot{0}/getUpdates?offset={1}&timeout=10",
                                Uri.EscapeDataString(botToken),
                                lastUpdateId + 1);

                            string json = "";
                            using (WebClient client = new WebClient())
                            {
                                client.Encoding = Encoding.UTF8;
                                json = client.DownloadString(url);
                            }

                            if (!string.IsNullOrEmpty(json))
                            {
                                ProcessTelegramUpdates(json, botToken, configuredChatId);
                            }
                        }
                    }
                    catch { }

                    Thread.Sleep(3000);
                }
            });
            pollingThread.IsBackground = true;
            pollingThread.Start();
        }

        public static void StopRemoteControlListener()
        {
            isPolling = false;
            try
            {
                if (pollingThread != null) pollingThread.Abort();
            }
            catch { }
        }

        private static void ProcessTelegramUpdates(string json, string botToken, string configuredChatId)
        {
            try
            {
                int index = 0;
                while ((index = json.IndexOf("\"update_id\":", index)) != -1)
                {
                    index += 12;
                    int endUpdateId = json.IndexOfAny(new char[] { ',', '}' }, index);
                    if (endUpdateId != -1)
                    {
                        string updateIdStr = json.Substring(index, endUpdateId - index).Trim();
                        long updateId;
                        if (long.TryParse(updateIdStr, out updateId))
                        {
                            if (updateId > lastUpdateId) lastUpdateId = updateId;
                        }
                    }

                    // Look for message text in this update chunk
                    int msgIndex = json.IndexOf("\"message\":", index);
                    int nextUpdateIndex = json.IndexOf("\"update_id\":", index);
                    if (msgIndex != -1 && (nextUpdateIndex == -1 || msgIndex < nextUpdateIndex))
                    {
                        // Check sender chatId
                        int chatIndex = json.IndexOf("\"chat\":", msgIndex);
                        if (chatIndex != -1)
                        {
                            int idIndex = json.IndexOf("\"id\":", chatIndex);
                            if (idIndex != -1)
                            {
                                idIndex += 5;
                                int endChatId = json.IndexOfAny(new char[] { ',', '}' }, idIndex);
                                string senderChatId = json.Substring(idIndex, endChatId - idIndex).Trim();

                                // Only execute commands from the authorized Admin Chat ID
                                if (senderChatId.Equals(configuredChatId, StringComparison.OrdinalIgnoreCase))
                                {
                                    int textIndex = json.IndexOf("\"text\":\"", msgIndex);
                                    if (textIndex != -1 && (nextUpdateIndex == -1 || textIndex < nextUpdateIndex))
                                    {
                                        textIndex += 8;
                                        int endText = json.IndexOf("\"", textIndex);
                                        if (endText != -1)
                                        {
                                            string text = json.Substring(textIndex, endText - textIndex).Trim();
                                            ExecuteRemoteCommand(text, botToken, configuredChatId);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private static void ExecuteRemoteCommand(string command, string botToken, string chatId)
        {
            if (string.IsNullOrEmpty(command)) return;
            string cmd = command.Trim();
            string myMachine = Environment.MachineName.ToUpperInvariant();

            // Command syntax examples:
            // /status or /status PCNAME
            // /lock or /lock PCNAME
            // /unlock or /unlock PCNAME
            // /timer 15 or /timer PCNAME 15
            // /help

            string[] parts = cmd.Split(' ');
            string action = parts[0].ToLowerInvariant();
            string targetDevice = parts.Length > 1 ? parts[1].ToUpperInvariant() : "";

            // Check if command is targeted to all devices or this specific device
            if (!string.IsNullOrEmpty(targetDevice) && !targetDevice.Equals(myMachine, StringComparison.OrdinalIgnoreCase) && !action.Equals("/timer", StringComparison.OrdinalIgnoreCase))
            {
                // Target is specified and doesn't match this PC
                return;
            }

            if (action == "/help" || action == "/start")
            {
                string helpMsg = "🛡️ *لوحة تحكم USB Port Shield عن بُعد:*\n\n" +
                                 "🔹 `/status` - فحص حالة هذا الجهاز\n" +
                                 "🔹 `/lock` - قفل منافذ USB فوراً\n" +
                                 "🔹 `/unlock` - فتح منافذ USB فوراً\n" +
                                 "🔹 `/timer 15` - فتح مؤقت لمدة (5, 15, 30, 60 دقيقة)\n" +
                                 "🔹 `/wp_on` - تفعيل وضع الحماية من النسخ (Read-Only)\n" +
                                 "🔹 `/wp_off` - السماح بنسخ الملفات (وضع عادي)\n" +
                                 "\n💡 يمكنك توجيه الأمر لجهاز محدد بكتابة اسمه بعد الأمر:\nمثال: `/lock " + Environment.MachineName + "`";
                SendTelegramAlert(botToken, chatId, helpMsg, false);
            }
            else if (action == "/status")
            {
                bool usbOpen = GetUsbStorageStateFunc != null ? GetUsbStorageStateFunc() : false;
                bool wpActive = GetWriteProtectStateFunc != null ? GetWriteProtectStateFunc() : false;

                string statusMsg = string.Format("📊 *تقرير حالة الجهاز عن بُعد:*\n\n" +
                                                 "💾 حالة المنافذ: {0}\n" +
                                                 "✍️ وضع القراءة فقط: {1}\n" +
                                                 "⏱️ التوقيت: {2:yyyy-MM-dd HH:mm:ss}",
                                                 usbOpen ? "🟢 مفتوحة ومتاحة" : "⛔ مقفلة ومحظورة",
                                                 wpActive ? "🛡️ مفعّل (حظر النسخ)" : "✍️ معطل (النسخ مسموح)",
                                                 DateTime.Now);
                SendTelegramAlert(botToken, chatId, statusMsg, true);
            }
            else if (action == "/lock")
            {
                if (SetUsbStorageStateFunc != null)
                {
                    SetUsbStorageStateFunc(false);
                    SendTelegramAlert(botToken, chatId, "⛔ تم تنفيذ الأمر عن بُعد: تم قفل منافذ USB بنجاح!", true);
                }
            }
            else if (action == "/unlock")
            {
                if (SetUsbStorageStateFunc != null)
                {
                    SetUsbStorageStateFunc(true);
                    SendTelegramAlert(botToken, chatId, "🟢 تم تنفيذ الأمر عن بُعد: تم فتح منافذ USB بنجاح!", true);
                }
            }
            else if (action == "/wp_on")
            {
                if (SetWriteProtectStateFunc != null)
                {
                    SetWriteProtectStateFunc(true);
                    SendTelegramAlert(botToken, chatId, "🛡️ تم تنفيذ الأمر عن بُعد: تم تفعيل وضع الحماية من النسخ (Read-Only)!", true);
                }
            }
            else if (action == "/wp_off")
            {
                if (SetWriteProtectStateFunc != null)
                {
                    SetWriteProtectStateFunc(false);
                    SendTelegramAlert(botToken, chatId, "✍️ تم تنفيذ الأمر عن بُعد: تم السماح بنسخ الملفات (Normal Mode)!", true);
                }
            }
            else if (action == "/timer")
            {
                int mins = 15;
                if (parts.Length > 1) int.TryParse(parts[1], out mins);
                if (parts.Length > 2) int.TryParse(parts[2], out mins);
                if (mins <= 0) mins = 15;

                if (StartAutoLockTimerFunc != null)
                {
                    StartAutoLockTimerFunc(mins);
                    SendTelegramAlert(botToken, chatId, string.Format("⏳ تم تفعيل المؤقت عن بُعد: فتح المنافذ لمدة {0} دقيقة وسيتم قفلها تلقائياً!", mins), true);
                }
            }
        }

        public static void SaveTelegramConfig(string botToken, string chatId)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RegKeyPath))
                {
                    if (key != null)
                    {
                        key.SetValue("BotToken", botToken, RegistryValueKind.String);
                        key.SetValue("ChatId", chatId, RegistryValueKind.String);
                    }
                }
            }
            catch { }
        }

        public static void LoadTelegramConfig(out string botToken, out string chatId)
        {
            botToken = "8815345940:AAFM52TD4C3Iz8oOm6tCUvMICY4uwkypo-I";
            chatId = "1669970731";
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegKeyPath))
                {
                    if (key != null)
                    {
                        string t = key.GetValue("BotToken") as string;
                        string c = key.GetValue("ChatId") as string;
                        if (!string.IsNullOrEmpty(t)) botToken = t;
                        if (!string.IsNullOrEmpty(c)) chatId = c;
                    }
                }
            }
            catch { }
        }
    }
    #endregion

    static class Program
    {
        private static Mutex singleInstanceMutex = null;

        [STAThread]
        static void Main(string[] args)
        {
            bool createdNew;
            singleInstanceMutex = new Mutex(true, "USBPortController_SingleInstance_App_Mutex", out createdNew);

            if (!createdNew)
            {
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (!IsAdministrator())
            {
                string msg = Loc.T(
                    "يتطلب هذا البرنامج صلاحيات كمسؤول (Administrator) للتحكم في منافذ النظام وسجل الويندوز.\n\nهل ترغب في إعادة تشغيل البرنامج كمسؤول الآن؟",
                    "This application requires Administrator privileges to control system ports and registry.\n\nDo you want to restart the application as Administrator now?"
                );
                string title = Loc.T("طلب صلاحيات المسؤول", "Administrator Rights Required");

                DialogResult res = MessageBox.Show(
                    msg,
                    title,
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    MessageBoxDefaultButton.Button1,
                    Loc.IsArabic ? (MessageBoxOptions.RightAlign | MessageBoxOptions.RtlReading) : 0
                );

                if (res == DialogResult.Yes)
                {
                    try
                    {
                        ProcessStartInfo startInfo = new ProcessStartInfo
                        {
                            UseShellExecute = true,
                            WorkingDirectory = Environment.CurrentDirectory,
                            FileName = Application.ExecutablePath,
                            Verb = "runas"
                        };
                        Process.Start(startInfo);
                    }
                    catch { }
                }
                return;
            }

            bool startInBackground = (args != null && args.Length > 0 && args[0].ToLower().Contains("background"));
            Application.Run(new UnifiedMainForm(startInBackground));
        }

        public static bool IsAdministrator()
        {
            try
            {
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }

    #region Auto-Start & Background Persistence Management
    public static class AutoStartManager
    {
        private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string AppName = "USBPortControllerShield";

        public static bool IsAutoStartEnabled()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunKeyPath))
                {
                    if (key != null)
                    {
                        object val = key.GetValue(AppName);
                        return val != null;
                    }
                }
            }
            catch { }
            return false;
        }

        public static void SetAutoStart(bool enable)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunKeyPath, true))
                {
                    if (key != null)
                    {
                        if (enable)
                        {
                            key.SetValue(AppName, "\"" + Application.ExecutablePath + "\" -background");
                        }
                        else
                        {
                            key.DeleteValue(AppName, false);
                        }
                    }
                }
            }
            catch { }
        }
    }
    #endregion

    #region Password Security Management
    public static class PasswordManager
    {
        private const string RegKeyPath = @"Software\USBPortController\Security";
        private const string HashValueName = "PasswordHash";
        private const string SaltValueName = "PasswordSalt";

        public static bool IsPasswordSet()
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegKeyPath))
                {
                    if (key != null)
                    {
                        string hash = key.GetValue(HashValueName) as string;
                        return !string.IsNullOrEmpty(hash);
                    }
                }
            }
            catch { }
            return false;
        }

        public static bool SetPassword(string newPassword)
        {
            try
            {
                byte[] saltBytes = new byte[16];
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(saltBytes);
                }
                string salt = Convert.ToBase64String(saltBytes);
                string hash = ComputeHash(newPassword, salt);

                using (RegistryKey key = Registry.CurrentUser.CreateSubKey(RegKeyPath))
                {
                    if (key != null)
                    {
                        key.SetValue(HashValueName, hash, RegistryValueKind.String);
                        key.SetValue(SaltValueName, salt, RegistryValueKind.String);
                        SecurityLogger.LogEvent("PASS_SET", Loc.T("تم تحديث كلمة السر الرئيسية بنجاح", "Master password configured successfully"));
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    Loc.T("خطأ أثناء حفظ كلمة السر: ", "Error saving password: ") + ex.Message,
                    Loc.T("خطأ", "Error"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
            return false;
        }

        public static bool VerifyPassword(string inputPassword)
        {
            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RegKeyPath))
                {
                    if (key != null)
                    {
                        string storedHash = key.GetValue(HashValueName) as string;
                        string storedSalt = key.GetValue(SaltValueName) as string;
                        if (!string.IsNullOrEmpty(storedHash) && !string.IsNullOrEmpty(storedSalt))
                        {
                            string calculatedHash = ComputeHash(inputPassword, storedSalt);
                            bool match = storedHash == calculatedHash;
                            if (match)
                            {
                                SecurityLogger.LogEvent("AUTH_SUCCESS", Loc.T("تم تسجيل الدخول بنجاح", "Successful authentication"));
                            }
                            else
                            {
                                SecurityLogger.LogEvent("AUTH_FAILED", Loc.T("محاولة دخول فاشلة بكلمة سر خاطئة!", "Failed authentication attempt!"));
                            }
                            return match;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private static string ComputeHash(string password, string salt)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] combinedBytes = Encoding.UTF8.GetBytes(password + salt);
                byte[] hashBytes = sha256.ComputeHash(combinedBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }
    }
    #endregion

    #region Unified Single-Window Form
    public class UnifiedMainForm : Form
    {
        private const int WM_DEVICECHANGE = 0x0219;
        private const int DBT_DEVICEARRIVAL = 0x8000;
        private const int DBT_DEVICEREMOVECOMPLETE = 0x8004;

        private enum CurrentViewType
        {
            Unlock,
            SetupPassword,
            Control,
            ChangePassword,
            ActivityLogs,
            AutoLockTimer,
            TelegramSettings,
            Whitelist
        }

        private CurrentViewType activeView = CurrentViewType.Unlock;

        private Panel contentCard;
        private Image logoImage;

        // UI Controls
        private Label lblUsbStatus;
        private Button btnToggleUsb;
        private Label lblWriteProtectStatus;
        private Button btnToggleWriteProtect;
        private Label lblAutoStartStatus;
        private Button btnToggleAutoStart;
        private Label lblLiveIndicator;
        private Label lblTimerStatus;
        private NotifyIcon trayIcon;

        // ===== Modern Design Color Palette =====
        private static readonly Color ClrBgDark = Color.FromArgb(10, 12, 20);
        private static readonly Color ClrBgGrad = Color.FromArgb(18, 24, 42);
        private static readonly Color ClrCardBg = Color.FromArgb(22, 30, 48);
        private static readonly Color ClrCardBorder = Color.FromArgb(40, 52, 80);
        private static readonly Color ClrInputBg = Color.FromArgb(12, 16, 30);
        private static readonly Color ClrAccentBlue = Color.FromArgb(56, 139, 253);
        private static readonly Color ClrAccentCyan = Color.FromArgb(34, 211, 238);
        private static readonly Color ClrAccentGreen = Color.FromArgb(16, 185, 129);
        private static readonly Color ClrAccentRed = Color.FromArgb(239, 68, 68);
        private static readonly Color ClrAccentOrange = Color.FromArgb(245, 158, 11);
        private static readonly Color ClrAccentPurple = Color.FromArgb(139, 92, 246);
        private static readonly Color ClrTextPrimary = Color.FromArgb(237, 242, 247);
        private static readonly Color ClrTextSecondary = Color.FromArgb(148, 163, 184);
        private static readonly Color ClrTextMuted = Color.FromArgb(100, 116, 139);
        private static readonly Color ClrBtnDefault = Color.FromArgb(35, 45, 65);
        private static readonly Color ClrSectionBg = Color.FromArgb(16, 22, 38);
        private static readonly Color ClrDivider = Color.FromArgb(38, 50, 72);

        public UnifiedMainForm(bool startInBackground = false)
        {
            LoadEmbeddedLogo();
            ApplyFormStyling();

            InitCardContainer();
            InitTrayIcon();

            AutoLockTimerManager.OnTick = (sec) =>
            {
                if (lblTimerStatus != null && !lblTimerStatus.IsDisposed)
                {
                    int m = sec / 60;
                    int s = sec % 60;
                    lblTimerStatus.Text = Loc.T(
                        string.Format("⏳ المؤقت: يغلق تلقائياً بعد {0:D2}:{1:D2}", m, s),
                        string.Format("⏳ Timer: Auto-locking in {0:D2}:{1:D2}", m, s)
                    );
                    lblTimerStatus.ForeColor = ClrAccentOrange;
                }
            };

            // Wire Remote Telegram Control Callbacks
            AlertNotifier.GetUsbStorageStateFunc = () => IsUsbStorageEnabled();
            AlertNotifier.SetUsbStorageStateFunc = (enable) =>
            {
                this.BeginInvoke((MethodInvoker)delegate
                {
                    SetUsbStorageEnabled(enable);
                    RefreshAllStatus();
                });
            };
            AlertNotifier.GetWriteProtectStateFunc = () => IsWriteProtectEnabled();
            AlertNotifier.SetWriteProtectStateFunc = (enable) =>
            {
                this.BeginInvoke((MethodInvoker)delegate
                {
                    SetWriteProtectEnabled(enable);
                    RefreshAllStatus();
                });
            };
            AlertNotifier.StartAutoLockTimerFunc = (mins) =>
            {
                this.BeginInvoke((MethodInvoker)delegate
                {
                    SetUsbStorageEnabled(true);
                    AutoLockTimerManager.StartTimer(mins, () =>
                    {
                        SetUsbStorageEnabled(false);
                        RefreshAllStatus();
                        SecurityLogger.LogEvent("AUTO_LOCK_TRIGGERED", Loc.T("انتهى وقت المؤقت وتم قفل منافذ USB تلقائياً", "Timer expired: USB ports auto-locked"));
                    });
                    RefreshAllStatus();
                });
            };

            // Start Telegram Remote Polling Listener
            AlertNotifier.StartRemoteControlListener();

            // Background Auto-Repair: ensure no USB devices remain stuck/disabled
            ThreadPool.QueueUserWorkItem(delegate
            {
                UsbHardwareManager.RepairDisabledUsbDevices();
            });

            if (!PasswordManager.IsPasswordSet())
            {
                ShowSetupPasswordView();
            }
            else
            {
                ShowUnlockView();
            }

            if (startInBackground)
            {
                this.WindowState = FormWindowState.Minimized;
                this.ShowInTaskbar = false;
                this.Hide();
            }
        }

        private void LoadEmbeddedLogo()
        {
            try
            {
                string exeDir = Path.GetDirectoryName(Application.ExecutablePath);
                string logoPath = Path.Combine(exeDir, "app_logo.jpg");
                if (File.Exists(logoPath))
                {
                    using (var fs = new FileStream(logoPath, FileMode.Open, FileAccess.Read))
                    {
                        logoImage = Image.FromStream(fs);
                    }
                }

                string icoPath = Path.Combine(exeDir, "app.ico");
                if (File.Exists(icoPath))
                {
                    this.Icon = new Icon(icoPath);
                }
            }
            catch { }
        }

        private void ApplyFormStyling()
        {
            this.Text = Loc.T("درع التحكم في منافذ USB (الإصدار المؤسسي)", "USB Port Controller Shield (Enterprise v2.0)");
            this.Size = new Size(580, 640);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = true;
            this.BackColor = ClrBgDark;
            this.RightToLeft = Loc.IsArabic ? RightToLeft.Yes : RightToLeft.No;
            this.RightToLeftLayout = false;
            this.Font = new Font("Segoe UI", 9.5F, FontStyle.Regular);
            this.DoubleBuffered = true;
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            base.OnPaintBackground(e);
            using (LinearGradientBrush brush = new LinearGradientBrush(
                this.ClientRectangle,
                ClrBgDark,
                ClrBgGrad,
                LinearGradientMode.ForwardDiagonal))
            {
                e.Graphics.FillRectangle(brush, this.ClientRectangle);
            }

            // Subtle top accent line
            using (LinearGradientBrush accentBrush = new LinearGradientBrush(
                new Rectangle(0, 0, this.ClientSize.Width, 3),
                ClrAccentBlue,
                ClrAccentPurple,
                LinearGradientMode.Horizontal))
            {
                e.Graphics.FillRectangle(accentBrush, 0, 0, this.ClientSize.Width, 3);
            }
        }

        private void InitCardContainer()
        {
            contentCard = new Panel
            {
                Location = new Point(20, 18),
                Size = new Size(524, 575),
                BackColor = ClrCardBg,
                Padding = new Padding(14)
            };
            this.Controls.Add(contentCard);
        }

        // ===== Helper: Create a styled section panel =====
        private Panel CreateSectionPanel(int x, int y, int w, int h)
        {
            Panel p = new Panel
            {
                Location = new Point(x, y),
                Size = new Size(w, h),
                BackColor = ClrSectionBg
            };
            return p;
        }

        // ===== Helper: Create a styled button =====
        private Button CreateStyledButton(string text, int x, int y, int w, int h, Color bgColor)
        {
            Button btn = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(w, h),
                BackColor = bgColor,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 0;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(
                Math.Min(bgColor.R + 25, 255),
                Math.Min(bgColor.G + 25, 255),
                Math.Min(bgColor.B + 25, 255));
            return btn;
        }

        // ===== Helper: Create a toolbar button =====
        private Button CreateToolbarButton(string text, int x, int y, int w)
        {
            Button btn = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Size = new Size(w, 28),
                BackColor = ClrBtnDefault,
                ForeColor = ClrTextPrimary,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btn.FlatAppearance.BorderSize = 0;
            btn.FlatAppearance.MouseOverBackColor = Color.FromArgb(50, 65, 90);
            return btn;
        }

        // ===== Helper: Create a horizontal divider =====
        private Label CreateDivider(int y, int cardW)
        {
            return new Label
            {
                Location = new Point(10, y),
                Size = new Size(cardW - 10, 1),
                BackColor = ClrDivider
            };
        }

        private void SwitchLanguage(AppLanguage newLang)
        {
            Loc.SetLanguage(newLang);
            ApplyFormStyling();

            switch (activeView)
            {
                case CurrentViewType.Unlock:
                    ShowUnlockView();
                    break;
                case CurrentViewType.SetupPassword:
                    ShowSetupPasswordView();
                    break;
                case CurrentViewType.Control:
                    ShowControlView();
                    break;
                case CurrentViewType.ChangePassword:
                    ShowChangePasswordView();
                    break;
                case CurrentViewType.ActivityLogs:
                    ShowActivityLogsView();
                    break;
                case CurrentViewType.AutoLockTimer:
                    ShowAutoLockTimerView();
                    break;
                case CurrentViewType.TelegramSettings:
                    ShowTelegramSettingsView();
                    break;
                case CurrentViewType.Whitelist:
                    ShowWhitelistView();
                    break;
            }

            UpdateTrayIconText();
        }

        private void InitTrayIcon()
        {
            try
            {
                Icon iconToUse = this.Icon != null ? this.Icon : SystemIcons.Shield;
                trayIcon = new NotifyIcon
                {
                    Icon = iconToUse,
                    Text = Loc.T("درع منافذ USB - الحماية نشطة", "USB Port Shield - Active"),
                    Visible = true
                };
                UpdateTrayContextMenu();
                trayIcon.DoubleClick += (s, e) => RestoreFromTray();
            }
            catch { }
        }

        private void UpdateTrayContextMenu()
        {
            if (trayIcon == null) return;
            ContextMenu contextMenu = new ContextMenu();
            contextMenu.MenuItems.Add(Loc.T("فتح لوحة التحكم", "Open Control Panel"), (s, e) => RestoreFromTray());
            contextMenu.MenuItems.Add(Loc.T("قفل البرنامج", "Lock Application"), (s, e) => { ShowUnlockView(); RestoreFromTray(); });
            contextMenu.MenuItems.Add("-");
            contextMenu.MenuItems.Add(Loc.T("إيقاف الخدمة والخروج", "Stop Service & Exit"), (s, e) => ExitApplication());
            trayIcon.ContextMenu = contextMenu;
        }

        private void UpdateTrayIconText()
        {
            if (trayIcon != null)
            {
                trayIcon.Text = Loc.T("درع منافذ USB - الحماية نشطة", "USB Port Shield - Active");
                UpdateTrayContextMenu();
            }
        }

        private void RestoreFromTray()
        {
            this.Show();
            this.WindowState = FormWindowState.Normal;
            this.ShowInTaskbar = true;
            this.BringToFront();
        }

        private void ExitApplication()
        {
            SecurityLogger.LogEvent("APP_EXIT", Loc.T("تم إيقاف خدمة الحماية والخروج من التطبيق", "Protection service stopped and app exited"));
            if (trayIcon != null)
            {
                trayIcon.Visible = false;
                trayIcon.Dispose();
            }
            Application.Exit();
        }

        private Button CreateLangSwitchButton()
        {
            Button btnLang = new Button
            {
                Text = Loc.IsArabic ? "🌐 EN" : "🌐 ع",
                Size = new Size(56, 28),
                BackColor = ClrBtnDefault,
                ForeColor = ClrTextPrimary,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnLang.FlatAppearance.BorderSize = 0;
            btnLang.FlatAppearance.MouseOverBackColor = Color.FromArgb(50, 65, 90);
            btnLang.Click += (s, e) =>
            {
                SwitchLanguage(Loc.IsArabic ? AppLanguage.English : AppLanguage.Arabic);
            };
            return btnLang;
        }

        private PictureBox CreateLogoHeader(int size = 44)
        {
            PictureBox pic = new PictureBox
            {
                Size = new Size(size, size),
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent
            };
            if (logoImage != null) pic.Image = logoImage;
            return pic;
        }

        #region View 1: شاشة فتح القفل
        private void ShowUnlockView()
        {
            activeView = CurrentViewType.Unlock;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 28;
            int centerX = (cardW - 360) / 2;

            // Language button top-right/left
            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(14, 14) : new Point(cardW - 42, 14);

            // Logo centered
            PictureBox picLogo = CreateLogoHeader(64);
            picLogo.Location = new Point((cardW - 64) / 2, 50);

            // Title
            Label lblTitle = new Label
            {
                Text = Loc.T("🔐 التطبيق محمي بكلمة سر", "🔐 Application is Locked"),
                ForeColor = ClrAccentBlue,
                Font = new Font("Segoe UI", 14F, FontStyle.Bold),
                Location = new Point(14, 125),
                Size = new Size(cardW, 30),
                TextAlign = ContentAlignment.MiddleCenter
            };

            // Subtitle
            Label lblDesc = new Label
            {
                Text = Loc.T("أدخل كلمة السر الرئيسية للوصول إلى لوحة التحكم", "Enter master password to access the control panel"),
                ForeColor = ClrTextSecondary,
                Font = new Font("Segoe UI", 9F),
                Location = new Point(14, 160),
                Size = new Size(cardW, 22),
                TextAlign = ContentAlignment.MiddleCenter
            };

            // Password section panel
            Panel pnlInput = CreateSectionPanel(centerX, 200, 360, 130);

            Label lblPassLabel = new Label
            {
                Text = Loc.T("كلمة السر:", "Password:"),
                ForeColor = ClrTextSecondary,
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(12, 12),
                Size = new Size(336, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            TextBox txtPassword = new TextBox
            {
                Location = new Point(12, 34),
                Size = new Size(336, 28),
                PasswordChar = '●',
                BackColor = ClrInputBg,
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 11F)
            };

            Label lblError = new Label
            {
                Text = "",
                ForeColor = ClrAccentRed,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Location = new Point(12, 68),
                Size = new Size(336, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Button btnUnlock = CreateStyledButton(
                Loc.T("🔓 فتح القفل", "🔓 Unlock"),
                12, 92, 336, 30, ClrAccentGreen);
            btnUnlock.Font = new Font("Segoe UI", 10F, FontStyle.Bold);

            pnlInput.Controls.Add(lblPassLabel);
            pnlInput.Controls.Add(txtPassword);
            pnlInput.Controls.Add(lblError);
            pnlInput.Controls.Add(btnUnlock);

            // Exit button
            Button btnExit = CreateStyledButton(
                Loc.T("خروج من التطبيق", "Exit Application"),
                centerX, 345, 360, 34, ClrBtnDefault);
            btnExit.Font = new Font("Segoe UI", 9F);
            btnExit.Click += (s, e) => ExitApplication();

            // Version label
            Label lblVersion = new Label
            {
                Text = "USB Port Shield v2.0 — Enterprise",
                ForeColor = ClrTextMuted,
                Font = new Font("Segoe UI", 7.5F),
                Location = new Point(14, 530),
                Size = new Size(cardW, 16),
                TextAlign = ContentAlignment.MiddleCenter
            };

            btnUnlock.Click += (s, e) =>
            {
                if (PasswordManager.VerifyPassword(txtPassword.Text))
                {
                    ShowControlView();
                }
                else
                {
                    lblError.Text = Loc.T("⚠ كلمة السر غير صحيحة! حاول مجدداً.", "⚠ Incorrect password! Please try again.");
                    txtPassword.SelectAll();
                    txtPassword.Focus();

                    string botToken, chatId;
                    AlertNotifier.LoadTelegramConfig(out botToken, out chatId);
                    if (!string.IsNullOrEmpty(botToken) && !string.IsNullOrEmpty(chatId))
                    {
                        AlertNotifier.SendTelegramAlert(botToken, chatId, "⚠️ تنبيه أمني: محاولة دخول فاشلة بكلمة سر غير صحيحة على جهاز: " + Environment.MachineName);
                    }
                }
            };

            contentCard.Controls.Add(btnLang);
            contentCard.Controls.Add(picLogo);
            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(lblDesc);
            contentCard.Controls.Add(pnlInput);
            contentCard.Controls.Add(btnExit);
            contentCard.Controls.Add(lblVersion);

            this.AcceptButton = btnUnlock;
            txtPassword.Focus();
        }
        #endregion

        #region View 2: إعداد كلمة السر لأول مرة
        private void ShowSetupPasswordView()
        {
            activeView = CurrentViewType.SetupPassword;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 28;
            int centerX = (cardW - 380) / 2;

            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(14, 14) : new Point(cardW - 42, 14);

            PictureBox picLogo = CreateLogoHeader(52);
            picLogo.Location = new Point((cardW - 52) / 2, 40);

            Label lblTitle = new Label
            {
                Text = Loc.T("🔒 تعيين كلمة سر رئيسية", "🔒 Set Master Password"),
                ForeColor = ClrAccentBlue,
                Font = new Font("Segoe UI", 13F, FontStyle.Bold),
                Location = new Point(14, 100),
                Size = new Size(cardW, 28),
                TextAlign = ContentAlignment.MiddleCenter
            };

            Label lblSubtitle = new Label
            {
                Text = Loc.T("لحماية الوصول إلى إعدادات التحكم بمنافذ USB", "To secure access to USB port control settings"),
                ForeColor = ClrTextSecondary,
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(14, 130),
                Size = new Size(cardW, 20),
                TextAlign = ContentAlignment.MiddleCenter
            };

            // Input section
            Panel pnlInput = CreateSectionPanel(centerX, 165, 380, 200);

            Label lblPass = new Label
            {
                Text = Loc.T("كلمة السر الجديدة:", "New Password:"),
                ForeColor = ClrTextSecondary,
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(14, 14),
                Size = new Size(352, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };
            TextBox txtNew = new TextBox { Location = new Point(14, 34), Size = new Size(352, 26), PasswordChar = '●', BackColor = ClrInputBg, ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 10F) };

            Label lblConf = new Label
            {
                Text = Loc.T("تأكيد كلمة السر:", "Confirm Password:"),
                ForeColor = ClrTextSecondary,
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(14, 70),
                Size = new Size(352, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };
            TextBox txtConf = new TextBox { Location = new Point(14, 90), Size = new Size(352, 26), PasswordChar = '●', BackColor = ClrInputBg, ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 10F) };

            Label lblErr = new Label
            {
                Text = "",
                ForeColor = ClrAccentRed,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Location = new Point(14, 124),
                Size = new Size(352, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Button btnSave = CreateStyledButton(
                Loc.T("حفظ ومتابعة ✔", "Save & Continue ✔"),
                14, 150, 352, 36, ClrAccentBlue);
            btnSave.Font = new Font("Segoe UI", 10F, FontStyle.Bold);

            pnlInput.Controls.Add(lblPass);
            pnlInput.Controls.Add(txtNew);
            pnlInput.Controls.Add(lblConf);
            pnlInput.Controls.Add(txtConf);
            pnlInput.Controls.Add(lblErr);
            pnlInput.Controls.Add(btnSave);

            btnSave.Click += (s, e) =>
            {
                if (string.IsNullOrEmpty(txtNew.Text))
                {
                    lblErr.Text = Loc.T("يرجى كتابة كلمة السر!", "Please enter a password!");
                    return;
                }
                if (txtNew.Text != txtConf.Text)
                {
                    lblErr.Text = Loc.T("كلمتا السر غير متطابقتين!", "Passwords do not match!");
                    return;
                }
                if (PasswordManager.SetPassword(txtNew.Text))
                {
                    MessageBox.Show(
                        Loc.T("تم تعيين كلمة السر بنجاح!", "Password configured successfully!"),
                        Loc.T("نجاح", "Success"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information
                    );
                    ShowControlView();
                }
            };

            contentCard.Controls.Add(btnLang);
            contentCard.Controls.Add(picLogo);
            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(lblSubtitle);
            contentCard.Controls.Add(pnlInput);

            this.AcceptButton = btnSave;
        }
        #endregion

        #region View 3: لوحة التحكم الرئيسية الكاملة
        private void ShowControlView()
        {
            activeView = CurrentViewType.Control;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 28;
            int sectionW = cardW - 20;

            // ===== Header Bar =====
            PictureBox picLogo = CreateLogoHeader(26);
            picLogo.Location = Loc.IsArabic ? new Point(cardW - 26, 10) : new Point(10, 10);

            Label lblTitle = new Label
            {
                Text = Loc.T("درع حماية USB", "USB Shield Pro"),
                ForeColor = ClrAccentCyan,
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                Location = Loc.IsArabic ? new Point(cardW - 155, 11) : new Point(40, 11),
                Size = new Size(120, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            // Toolbar buttons
            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(cardW - 220, 9) : new Point(165, 9);

            Button btnLogs = CreateToolbarButton(Loc.T("📋 السجل", "📋 Logs"), Loc.IsArabic ? (cardW - 290) : 225, 9, 66);
            btnLogs.Click += (s, e) => ShowActivityLogsView();

            Button btnTimer = CreateToolbarButton(Loc.T("⏳ مؤقت", "⏳ Timer"), Loc.IsArabic ? (cardW - 358) : 295, 9, 64);
            btnTimer.Click += (s, e) => ShowAutoLockTimerView();

            Button btnPass = CreateToolbarButton("🔑", Loc.IsArabic ? 42 : 363, 9, 32);
            btnPass.Click += (s, e) => ShowChangePasswordView();

            Button btnLock = CreateToolbarButton("🔒", Loc.IsArabic ? 8 : 399, 9, 32);
            btnLock.Click += (s, e) => ShowUnlockView();

            // ===== Timer Status =====
            lblTimerStatus = new Label
            {
                Text = AutoLockTimerManager.IsTimerRunning
                    ? Loc.T(string.Format("⏳ المؤقت نشط: يغلق بعد {0:D2}:{1:D2}", AutoLockTimerManager.RemainingSeconds / 60, AutoLockTimerManager.RemainingSeconds % 60), "⏳ Auto-locking in active timer")
                    : "",
                ForeColor = ClrAccentOrange,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Location = new Point(10, 42),
                Size = new Size(cardW, 18),
                TextAlign = ContentAlignment.MiddleCenter
            };

            // ===== SECTION 1: USB Storage =====
            Panel pnlUsb = CreateSectionPanel(10, 64, sectionW, 78);

            lblUsbStatus = new Label
            {
                Text = Loc.T("💾 منافذ الفلاشات: جاري الفحص...", "💾 USB Storage: Checking..."),
                ForeColor = ClrTextPrimary,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Location = new Point(10, 8),
                Size = new Size(sectionW - 20, 22),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            btnToggleUsb = new Button
            {
                Text = Loc.T("تغيير الحالة", "Toggle Status"),
                Location = new Point(10, 34),
                Size = new Size(sectionW - 20, 36),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand,
                ForeColor = Color.White
            };
            btnToggleUsb.FlatAppearance.BorderSize = 0;
            btnToggleUsb.Click += BtnToggleUsb_Click;

            pnlUsb.Controls.Add(lblUsbStatus);
            pnlUsb.Controls.Add(btnToggleUsb);

            // ===== SECTION 2: Write Protection =====
            Panel pnlWP = CreateSectionPanel(10, 148, sectionW, 78);

            lblWriteProtectStatus = new Label
            {
                Text = Loc.T("✍️ الحماية من النسخ: جاري الفحص...", "✍️ Write Protection: Checking..."),
                ForeColor = ClrTextPrimary,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Location = new Point(10, 8),
                Size = new Size(sectionW - 20, 22),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            btnToggleWriteProtect = new Button
            {
                Text = Loc.T("تغيير وضع الحماية", "Toggle Protection"),
                Location = new Point(10, 34),
                Size = new Size(sectionW - 20, 36),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand,
                ForeColor = Color.White
            };
            btnToggleWriteProtect.FlatAppearance.BorderSize = 0;
            btnToggleWriteProtect.Click += BtnToggleWriteProtect_Click;

            pnlWP.Controls.Add(lblWriteProtectStatus);
            pnlWP.Controls.Add(btnToggleWriteProtect);

            // ===== SECTION 3: Auto-Start =====
            Panel pnlAS = CreateSectionPanel(10, 232, sectionW, 78);

            lblAutoStartStatus = new Label
            {
                Text = Loc.T("🔄 الإقلاع مع الويندوز: جاري الفحص...", "🔄 Startup: Checking..."),
                ForeColor = ClrTextPrimary,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Location = new Point(10, 8),
                Size = new Size(sectionW - 20, 22),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            btnToggleAutoStart = new Button
            {
                Text = Loc.T("تبديل وضع الإقلاع", "Toggle Startup Mode"),
                Location = new Point(10, 34),
                Size = new Size(sectionW - 20, 36),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand,
                ForeColor = Color.White
            };
            btnToggleAutoStart.FlatAppearance.BorderSize = 0;
            btnToggleAutoStart.Click += BtnToggleAutoStart_Click;

            pnlAS.Controls.Add(lblAutoStartStatus);
            pnlAS.Controls.Add(btnToggleAutoStart);

            // ===== Divider =====
            Label divider1 = CreateDivider(318, cardW);

            // ===== Feature buttons row =====
            int halfW = (sectionW - 10) / 2;

            Button btnWhitelist = CreateStyledButton(
                Loc.T("🛡️ القائمة البيضاء", "🛡️ Device Whitelist"),
                Loc.IsArabic ? (10 + halfW + 10) : 10, 326, halfW, 40, ClrAccentGreen);
            btnWhitelist.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            btnWhitelist.Click += (s, e) => ShowWhitelistView();

            Button btnTgAlerts = CreateStyledButton(
                Loc.T("🔔 تنبيهات Telegram", "🔔 Telegram Alerts"),
                Loc.IsArabic ? 10 : (10 + halfW + 10), 326, halfW, 40, Color.FromArgb(14, 116, 144));
            btnTgAlerts.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            btnTgAlerts.Click += (s, e) => ShowTelegramSettingsView();

            // ===== Exit button =====
            Button btnStopService = CreateStyledButton(
                Loc.T("🛑 إيقاف الحماية والخروج", "🛑 Stop Protection & Exit"),
                10, 374, sectionW, 38, ClrAccentRed);
            btnStopService.Click += (s, e) => ExitApplication();

            // ===== Live Monitor =====
            Label divider2 = CreateDivider(420, cardW);

            lblLiveIndicator = new Label
            {
                Text = Loc.T("🟢 درع الحماية نشط ومستمر — يكتشف الأجهزة تلقائياً", "🟢 Protection Active & Persistent — Auto-detects Devices"),
                ForeColor = ClrTextMuted,
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(10, 428),
                Size = new Size(cardW, 20),
                TextAlign = ContentAlignment.MiddleCenter
            };

            // ===== Add all to contentCard =====
            contentCard.Controls.Add(picLogo);
            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(btnLang);
            contentCard.Controls.Add(btnLogs);
            contentCard.Controls.Add(btnTimer);
            contentCard.Controls.Add(btnPass);
            contentCard.Controls.Add(btnLock);
            contentCard.Controls.Add(lblTimerStatus);
            contentCard.Controls.Add(pnlUsb);
            contentCard.Controls.Add(pnlWP);
            contentCard.Controls.Add(pnlAS);
            contentCard.Controls.Add(divider1);
            contentCard.Controls.Add(btnWhitelist);
            contentCard.Controls.Add(btnTgAlerts);
            contentCard.Controls.Add(btnStopService);
            contentCard.Controls.Add(divider2);
            contentCard.Controls.Add(lblLiveIndicator);

            RefreshAllStatus();
        }
        #endregion

        #region View 4: شاشة سجل الأحداث الأمنية (Activity Logs)
        private void ShowActivityLogsView()
        {
            activeView = CurrentViewType.ActivityLogs;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 28;

            Label lblTitle = new Label
            {
                Text = Loc.T("📋 سجل النشاط والأحداث الأمنية", "📋 Security Activity & Event Logs"),
                ForeColor = ClrAccentBlue,
                Font = new Font("Segoe UI", 12F, FontStyle.Bold),
                Location = new Point(14, 12),
                Size = new Size(cardW, 26),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label divider = CreateDivider(42, cardW);

            ListBox listLogs = new ListBox
            {
                Location = new Point(14, 50),
                Size = new Size(cardW - 14, 380),
                BackColor = ClrSectionBg,
                ForeColor = ClrTextSecondary,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 8.5F),
                HorizontalScrollbar = true
            };

            string[] logs = SecurityLogger.ReadRecentLogs(100);
            if (logs.Length == 0)
            {
                listLogs.Items.Add(Loc.T("لا توجد أحداث مسجلة حتى الآن.", "No events recorded yet."));
            }
            else
            {
                for (int i = logs.Length - 1; i >= 0; i--)
                {
                    listLogs.Items.Add(logs[i]);
                }
            }

            int btnW = (cardW - 30) / 3;

            Button btnExport = CreateStyledButton(
                Loc.T("💾 تصدير", "💾 Export"),
                Loc.IsArabic ? (cardW - btnW) : 14, 440, btnW, 34, ClrAccentBlue);
            btnExport.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            btnExport.Click += (s, e) =>
            {
                try
                {
                    SaveFileDialog sfd = new SaveFileDialog
                    {
                        Filter = "Text Log (*.txt)|*.txt|CSV File (*.csv)|*.csv",
                        FileName = "USB_Security_Report_" + DateTime.Now.ToString("yyyyMMdd_HHmmss")
                    };
                    if (sfd.ShowDialog() == DialogResult.OK)
                    {
                        File.Copy(SecurityLogger.GetLogPath(), sfd.FileName, true);
                        MessageBox.Show(Loc.T("تم تصدير السجل بنجاح!", "Log exported successfully!"), Loc.T("نجاح", "Success"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
                catch (Exception ex) { MessageBox.Show(ex.Message); }
            };

            Button btnClear = CreateStyledButton(
                Loc.T("🗑️ مسح", "🗑️ Clear"),
                14 + btnW + 4, 440, btnW, 34, ClrAccentRed);
            btnClear.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            btnClear.Click += (s, e) =>
            {
                SecurityLogger.ClearLogs();
                ShowActivityLogsView();
            };

            Button btnBack = CreateStyledButton(
                Loc.T("↩ رجوع", "↩ Back"),
                Loc.IsArabic ? 14 : (14 + 2 * (btnW + 4)), 440, btnW, 34, ClrBtnDefault);
            btnBack.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            btnBack.Click += (s, e) => ShowControlView();

            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(divider);
            contentCard.Controls.Add(listLogs);
            contentCard.Controls.Add(btnExport);
            contentCard.Controls.Add(btnClear);
            contentCard.Controls.Add(btnBack);
        }
        #endregion

        #region View 5: شاشة المؤقت للفتح المؤقت (Auto-Lock Timer)
        private void ShowAutoLockTimerView()
        {
            activeView = CurrentViewType.AutoLockTimer;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 28;

            Label lblTitle = new Label
            {
                Text = Loc.T("⏳ مؤقت الفتح المؤقت والقفل الذاتي", "⏳ Temporary Unlock & Auto-Lock Timer"),
                ForeColor = ClrAccentBlue,
                Font = new Font("Segoe UI", 12F, FontStyle.Bold),
                Location = new Point(14, 12),
                Size = new Size(cardW, 26),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblDesc = new Label
            {
                Text = Loc.T(
                    "فتح المنافذ لفترة محددة ثم القفل تلقائياً عند انتهاء الوقت:",
                    "Open ports temporarily; auto-lock when time expires:"
                ),
                ForeColor = ClrTextSecondary,
                Font = new Font("Segoe UI", 9F),
                Location = new Point(14, 42),
                Size = new Size(cardW, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label divider = CreateDivider(70, cardW);

            // Timer preset buttons
            int[] durations = new int[] { 5, 15, 30, 60 };
            string[] durLabels = new string[] {
                Loc.T("⏱️ 5 دقائق", "⏱️ 5 Minutes"),
                Loc.T("⏱️ 15 دقيقة", "⏱️ 15 Minutes"),
                Loc.T("⏱️ 30 دقيقة", "⏱️ 30 Minutes"),
                Loc.T("⏱️ ساعة كاملة", "⏱️ 1 Hour")
            };

            Color[] durColors = new Color[] {
                Color.FromArgb(30, 64, 175),
                Color.FromArgb(30, 58, 138),
                Color.FromArgb(88, 28, 135),
                Color.FromArgb(127, 29, 29)
            };

            for (int i = 0; i < durations.Length; i++)
            {
                int min = durations[i];
                Button btnPreset = CreateStyledButton(durLabels[i], 14, 82 + (i * 50), cardW - 14, 42, durColors[i]);
                btnPreset.Click += (s, e) =>
                {
                    SetUsbStorageEnabled(true);
                    AutoLockTimerManager.StartTimer(min, () =>
                    {
                        SetUsbStorageEnabled(false);
                        RefreshAllStatus();
                        SecurityLogger.LogEvent("AUTO_LOCK_TRIGGERED", Loc.T("انتهى وقت المؤقت وتم قفل منافذ USB تلقائياً", "Timer expired: USB ports auto-locked"));
                        if (trayIcon != null)
                        {
                            trayIcon.ShowBalloonTip(3000, Loc.T("قفل منافذ USB تلقائياً", "USB Ports Auto-Locked"), Loc.T("انتهت المدة المحددة وتم تأمين المنافذ وقفلها فوراً.", "Timer expired. USB ports are now securely locked."), ToolTipIcon.Warning);
                        }
                    });
                    MessageBox.Show(
                        Loc.T("تم فتح المنافذ بنجاح، وسيتم قفلها تلقائياً بعد " + min + " دقيقة!", "Ports opened! They will auto-lock in " + min + " minutes!"),
                        Loc.T("بدء المؤقت", "Timer Started"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information
                    );
                    ShowControlView();
                };
                contentCard.Controls.Add(btnPreset);
            }

            if (AutoLockTimerManager.IsTimerRunning)
            {
                Button btnCancelTimer = CreateStyledButton(
                    Loc.T("🛑 إيقاف المؤقت وإلغاؤه", "🛑 Cancel & Stop Timer"),
                    14, 292, cardW - 14, 42, ClrAccentRed);
                btnCancelTimer.Click += (s, e) =>
                {
                    AutoLockTimerManager.StopTimer();
                    MessageBox.Show(Loc.T("تم إيقاف المؤقت بنجاح!", "Timer cancelled!"), Loc.T("إلغاء المؤقت", "Timer Cancelled"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    ShowControlView();
                };
                contentCard.Controls.Add(btnCancelTimer);
            }

            Button btnBack = CreateStyledButton(
                Loc.T("↩ رجوع", "↩ Back"),
                14, 345, cardW - 14, 38, ClrBtnDefault);
            btnBack.Click += (s, e) => ShowControlView();

            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(lblDesc);
            contentCard.Controls.Add(divider);
            contentCard.Controls.Add(btnBack);
        }
        #endregion

        #region View 6: شاشة إعدادات تنبيهات تيليجرام
        private void ShowTelegramSettingsView()
        {
            activeView = CurrentViewType.TelegramSettings;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 28;

            Label lblTitle = new Label
            {
                Text = Loc.T("🔔 إعدادات تنبيهات Telegram", "🔔 Telegram Alert Settings"),
                ForeColor = ClrAccentBlue,
                Font = new Font("Segoe UI", 12F, FontStyle.Bold),
                Location = new Point(14, 12),
                Size = new Size(cardW, 26),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblDesc = new Label
            {
                Text = Loc.T(
                    "ربط البرنامج ببوت Telegram للإشعارات الفورية عند أي حدث أمني:",
                    "Connect to Telegram bot for instant security notifications:"
                ),
                ForeColor = ClrTextSecondary,
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(14, 42),
                Size = new Size(cardW, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label divider = CreateDivider(70, cardW);

            string curToken, curChatId;
            AlertNotifier.LoadTelegramConfig(out curToken, out curChatId);

            // Input section
            Panel pnlInput = CreateSectionPanel(14, 80, cardW - 14, 170);

            Label lblToken = new Label { Text = Loc.T("رمز البوت (Bot Token):", "Bot Token:"), ForeColor = ClrTextSecondary, Font = new Font("Segoe UI", 8.5F), Location = new Point(12, 12), Size = new Size(cardW - 38, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtToken = new TextBox { Text = curToken, Location = new Point(12, 32), Size = new Size(cardW - 38, 24), BackColor = ClrInputBg, ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 9F) };

            Label lblChat = new Label { Text = Loc.T("معرف المحادثة (Chat ID):", "Chat ID:"), ForeColor = ClrTextSecondary, Font = new Font("Segoe UI", 8.5F), Location = new Point(12, 66), Size = new Size(cardW - 38, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtChat = new TextBox { Text = curChatId, Location = new Point(12, 86), Size = new Size(cardW - 38, 24), BackColor = ClrInputBg, ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 9F) };

            Button btnTest = CreateStyledButton(
                Loc.T("📨 إرسال تنبيه تجريبي", "📨 Send Test Alert"),
                12, 122, cardW - 38, 36, Color.FromArgb(14, 116, 144));
            btnTest.Click += (s, e) =>
            {
                if (string.IsNullOrEmpty(txtToken.Text) || string.IsNullOrEmpty(txtChat.Text))
                {
                    MessageBox.Show(Loc.T("يرجى إدخال رمز البوت ومعرف المحادثة أولاً!", "Please enter Bot Token and Chat ID!"), Loc.T("تنبيه", "Warning"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                AlertNotifier.SendTelegramAlert(txtToken.Text, txtChat.Text, "🧪 رسالة تجريبية من درع منافذ USB: تم الربط بنجاح!");
                MessageBox.Show(Loc.T("تم إرسال التنبيه التجريبي! تفقد حسابك على تيليجرام.", "Test alert sent! Check your Telegram."), Loc.T("نجاح", "Success"), MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            pnlInput.Controls.Add(lblToken);
            pnlInput.Controls.Add(txtToken);
            pnlInput.Controls.Add(lblChat);
            pnlInput.Controls.Add(txtChat);
            pnlInput.Controls.Add(btnTest);

            int halfW = (cardW - 20) / 2;

            Button btnSave = CreateStyledButton(
                Loc.T("💾 حفظ الإعدادات", "💾 Save Settings"),
                Loc.IsArabic ? (14 + halfW + 6) : 14, 265, halfW, 38, ClrAccentBlue);
            btnSave.Click += (s, e) =>
            {
                AlertNotifier.SaveTelegramConfig(txtToken.Text, txtChat.Text);
                MessageBox.Show(Loc.T("تم حفظ إعدادات التنبيهات بنجاح!", "Settings saved successfully!"), Loc.T("نجاح", "Success"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                ShowControlView();
            };

            Button btnBack = CreateStyledButton(
                Loc.T("↩ رجوع", "↩ Back"),
                Loc.IsArabic ? 14 : (14 + halfW + 6), 265, halfW, 38, ClrBtnDefault);
            btnBack.Click += (s, e) => ShowControlView();

            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(lblDesc);
            contentCard.Controls.Add(divider);
            contentCard.Controls.Add(pnlInput);
            contentCard.Controls.Add(btnSave);
            contentCard.Controls.Add(btnBack);
        }
        #endregion

        #region View 8: شاشة إدارة القائمة البيضاء للأجهزة المصرحة
        private void ShowWhitelistView()
        {
            activeView = CurrentViewType.Whitelist;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 28;

            Label lblTitle = new Label
            {
                Text = Loc.T("🛡️ القائمة البيضاء — الأجهزة المصرح بها", "🛡️ Authorized Devices Whitelist"),
                ForeColor = ClrAccentBlue,
                Font = new Font("Segoe UI", 12F, FontStyle.Bold),
                Location = new Point(10, 8),
                Size = new Size(cardW, 26),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            // Whitelist toggle
            bool isWhitelistEnabled = WhitelistManager.IsWhitelistModeEnabled();
            Panel pnlToggle = CreateSectionPanel(10, 38, cardW - 6, 30);
            CheckBox chkEnableWhitelist = new CheckBox
            {
                Text = Loc.T("  تفعيل: حظر الكل عدا المصرح بهم", "  Enable: Block all except authorized"),
                Checked = isWhitelistEnabled,
                ForeColor = isWhitelistEnabled ? ClrAccentGreen : ClrTextSecondary,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(8, 4),
                Size = new Size(cardW - 30, 22),
                Cursor = Cursors.Hand
            };
            chkEnableWhitelist.CheckedChanged += (s, e) =>
            {
                chkEnableWhitelist.ForeColor = chkEnableWhitelist.Checked ? ClrAccentGreen : ClrTextSecondary;
                WhitelistManager.SetWhitelistModeEnabled(chkEnableWhitelist.Checked);
                SecurityLogger.LogEvent(chkEnableWhitelist.Checked ? "WHITELIST_MODE_ENABLED" : "WHITELIST_MODE_DISABLED",
                    Loc.T(chkEnableWhitelist.Checked ? "تم تفعيل حظر الفلاشات غير المصرح بها" : "تم تعطيل وضع القائمة البيضاء",
                          chkEnableWhitelist.Checked ? "Whitelist mode enforced" : "Whitelist mode disabled"));

                if (chkEnableWhitelist.Checked)
                {
                    var devices = WhitelistManager.GetWhitelistedDevices();
                    if (devices.Count > 0)
                    {
                        SetUsbStorageEnabled(true);
                        ThreadPool.QueueUserWorkItem(delegate
                        {
                            try
                            {
                                ProcessStartInfo psi = new ProcessStartInfo("pnputil.exe", "/scan-devices")
                                {
                                    CreateNoWindow = true,
                                    UseShellExecute = false,
                                    WindowStyle = ProcessWindowStyle.Hidden
                                };
                                using (Process p = Process.Start(psi))
                                {
                                    if (p != null) p.WaitForExit(3000);
                                }
                            }
                            catch { }
                        });
                    }
                }
            };
            pnlToggle.Controls.Add(chkEnableWhitelist);

            // ===== Connected drives section =====
            Label lblConnectedTitle = new Label
            {
                Text = Loc.T("🔌 الفلاشات المتصلة حالياً:", "🔌 Currently Connected USB Drives:"),
                ForeColor = ClrAccentCyan,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(10, 74),
                Size = new Size(cardW, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            ComboBox cmbConnectedDrives = new ComboBox
            {
                Location = new Point(10, 94),
                Size = new Size(cardW - 140, 26),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = ClrInputBg,
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F)
            };

            Button btnRefreshDrives = CreateStyledButton(
                Loc.T("🔄 فحص", "🔄 Scan"),
                cardW - 128, 93, 60, 28, ClrBtnDefault);
            btnRefreshDrives.Font = new Font("Segoe UI", 8F, FontStyle.Bold);

            Button btnAddCurrent = CreateStyledButton(
                Loc.T("➕ تصريح", "➕ Add"),
                cardW - 64, 93, 68, 28, ClrAccentGreen);
            btnAddCurrent.Font = new Font("Segoe UI", 8F, FontStyle.Bold);

            Action refreshConnectedDrives = () =>
            {
                cmbConnectedDrives.Items.Clear();
                var drives = WhitelistManager.GetConnectedUsbDrives();
                if (drives.Count == 0)
                {
                    cmbConnectedDrives.Items.Add(Loc.T("لا توجد فلاشات (أدخل فلاشة واضغط فحص)", "No USB drives (Insert & click Scan)"));
                    cmbConnectedDrives.SelectedIndex = 0;
                }
                else
                {
                    foreach (var d in drives) cmbConnectedDrives.Items.Add(d);
                    cmbConnectedDrives.SelectedIndex = 0;
                }
            };
            refreshConnectedDrives();

            btnRefreshDrives.Click += (s, e) => refreshConnectedDrives();

            // ===== Whitelisted devices list =====
            Label divider1 = CreateDivider(128, cardW);

            Label lblWhitelistTitle = new Label
            {
                Text = Loc.T("📋 الأجهزة المصرح لها:", "📋 Authorized Devices:"),
                ForeColor = ClrTextPrimary,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(10, 134),
                Size = new Size(cardW, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            ListBox listDevices = new ListBox
            {
                Location = new Point(10, 154),
                Size = new Size(cardW - 6, 195),
                BackColor = ClrSectionBg,
                ForeColor = ClrTextPrimary,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9F)
            };

            Action refreshWhitelist = () =>
            {
                listDevices.Items.Clear();
                var devices = WhitelistManager.GetWhitelistedDevices();
                if (devices.Count == 0)
                {
                    listDevices.Items.Add(Loc.T("لا توجد أجهزة مضافة حتى الآن.", "No authorized devices yet."));
                }
                else
                {
                    foreach (var d in devices)
                    {
                        listDevices.Items.Add(string.Format("🔹 {0}  [{1}]  ({2})", d.Name, d.DeviceId, d.AddedDate));
                    }
                }
            };
            refreshWhitelist();

            btnAddCurrent.Click += (s, e) =>
            {
                if (cmbConnectedDrives.SelectedIndex >= 0)
                {
                    string selected = cmbConnectedDrives.SelectedItem.ToString();
                    if (!selected.Contains("لا توجد") && !selected.Contains("No USB"))
                    {
                        WhitelistManager.AddDevice(selected, selected);
                        refreshWhitelist();
                        
                        SetUsbStorageEnabled(true);
                        ThreadPool.QueueUserWorkItem(delegate
                        {
                            try
                            {
                                ProcessStartInfo psi = new ProcessStartInfo("pnputil.exe", "/scan-devices")
                                {
                                    CreateNoWindow = true,
                                    UseShellExecute = false,
                                    WindowStyle = ProcessWindowStyle.Hidden
                                };
                                using (Process p = Process.Start(psi))
                                {
                                    if (p != null) p.WaitForExit(3000);
                                }
                            }
                            catch { }
                        });

                        MessageBox.Show(Loc.T("تمت إضافة الفلاشة وتصريحها بنجاح!", "USB drive authorized successfully!"), Loc.T("نجاح", "Success"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            };

            // ===== Manual add section =====
            Label divider2 = CreateDivider(355, cardW);

            Label lblAddDesc = new Label
            {
                Text = Loc.T("إضافة يدوية بالاسم:", "Add manually by name:"),
                ForeColor = ClrTextMuted,
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(10, 362),
                Size = new Size(cardW, 16),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            TextBox txtDevName = new TextBox
            {
                Location = new Point(10, 380),
                Size = new Size(cardW - 116, 26),
                BackColor = ClrInputBg,
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 9.5F)
            };

            Button btnAddManual = CreateStyledButton(
                Loc.T("➕ إضافة", "➕ Add"),
                cardW - 100, 379, 104, 28, ClrAccentBlue);
            btnAddManual.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            btnAddManual.Click += (s, e) =>
            {
                if (string.IsNullOrEmpty(txtDevName.Text.Trim())) return;
                string dev = txtDevName.Text.Trim();
                WhitelistManager.AddDevice(dev, dev);
                txtDevName.Clear();
                refreshWhitelist();
            };

            // ===== Bottom action buttons =====
            int thirdW = (cardW - 16) / 3;

            Button btnRemove = CreateStyledButton(
                Loc.T("🗑️ حذف المحدد", "🗑️ Remove"),
                10, 416, thirdW, 34, ClrAccentRed);
            btnRemove.Font = new Font("Segoe UI", 8.5F, FontStyle.Bold);
            btnRemove.Click += (s, e) =>
            {
                if (listDevices.SelectedIndex >= 0)
                {
                    var devices = WhitelistManager.GetWhitelistedDevices();
                    if (listDevices.SelectedIndex < devices.Count)
                    {
                        WhitelistManager.RemoveDevice(devices[listDevices.SelectedIndex].DeviceId);
                        refreshWhitelist();
                    }
                }
            };

            Button btnRefreshAll = CreateStyledButton(
                Loc.T("🔄 تحديث", "🔄 Refresh"),
                10 + thirdW + 4, 416, thirdW, 34, ClrBtnDefault);
            btnRefreshAll.Font = new Font("Segoe UI", 8.5F, FontStyle.Bold);
            btnRefreshAll.Click += (s, e) =>
            {
                refreshConnectedDrives();
                refreshWhitelist();
            };

            Button btnBack = CreateStyledButton(
                Loc.T("↩ رجوع", "↩ Back"),
                10 + 2 * (thirdW + 4), 416, thirdW, 34, ClrBtnDefault);
            btnBack.Font = new Font("Segoe UI", 8.5F, FontStyle.Bold);
            btnBack.Click += (s, e) => ShowControlView();

            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(pnlToggle);
            contentCard.Controls.Add(lblConnectedTitle);
            contentCard.Controls.Add(cmbConnectedDrives);
            contentCard.Controls.Add(btnRefreshDrives);
            contentCard.Controls.Add(btnAddCurrent);
            contentCard.Controls.Add(divider1);
            contentCard.Controls.Add(lblWhitelistTitle);
            contentCard.Controls.Add(listDevices);
            contentCard.Controls.Add(divider2);
            contentCard.Controls.Add(lblAddDesc);
            contentCard.Controls.Add(txtDevName);
            contentCard.Controls.Add(btnAddManual);
            contentCard.Controls.Add(btnRemove);
            contentCard.Controls.Add(btnRefreshAll);
            contentCard.Controls.Add(btnBack);
        }
        #endregion

        #region View 7: شاشة تغيير كلمة السر
        private void ShowChangePasswordView()
        {
            activeView = CurrentViewType.ChangePassword;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 28;
            int centerX = (cardW - 400) / 2;

            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(14, 12) : new Point(cardW - 42, 12);

            Label lblTitle = new Label
            {
                Text = Loc.T("🔑 تغيير كلمة السر الرئيسية", "🔑 Change Master Password"),
                ForeColor = ClrAccentBlue,
                Font = new Font("Segoe UI", 12F, FontStyle.Bold),
                Location = new Point(14, 14),
                Size = new Size(cardW - 60, 26),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label divider = CreateDivider(46, cardW);

            Panel pnlInput = CreateSectionPanel(centerX, 58, 400, 230);

            Label lblCurrent = new Label { Text = Loc.T("كلمة السر الحالية:", "Current Password:"), ForeColor = ClrTextSecondary, Font = new Font("Segoe UI", 8.5F), Location = new Point(14, 14), Size = new Size(372, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtCurrent = new TextBox { Location = new Point(14, 34), Size = new Size(372, 26), PasswordChar = '●', BackColor = ClrInputBg, ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 10F) };

            Label lblNew = new Label { Text = Loc.T("كلمة السر الجديدة:", "New Password:"), ForeColor = ClrTextSecondary, Font = new Font("Segoe UI", 8.5F), Location = new Point(14, 70), Size = new Size(372, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtNew = new TextBox { Location = new Point(14, 90), Size = new Size(372, 26), PasswordChar = '●', BackColor = ClrInputBg, ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 10F) };

            Label lblConfirm = new Label { Text = Loc.T("تأكيد كلمة السر:", "Confirm Password:"), ForeColor = ClrTextSecondary, Font = new Font("Segoe UI", 8.5F), Location = new Point(14, 126), Size = new Size(372, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtConfirm = new TextBox { Location = new Point(14, 146), Size = new Size(372, 26), PasswordChar = '●', BackColor = ClrInputBg, ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle, Font = new Font("Segoe UI", 10F) };

            int halfBtnW = 180;
            Button btnSave = CreateStyledButton(
                Loc.T("💾 حفظ", "💾 Save"),
                14, 186, halfBtnW, 34, ClrAccentBlue);

            Button btnBack = CreateStyledButton(
                Loc.T("↩ رجوع", "↩ Back"),
                14 + halfBtnW + 12, 186, halfBtnW, 34, ClrBtnDefault);
            btnBack.Click += (s, e) => ShowControlView();

            pnlInput.Controls.Add(lblCurrent);
            pnlInput.Controls.Add(txtCurrent);
            pnlInput.Controls.Add(lblNew);
            pnlInput.Controls.Add(txtNew);
            pnlInput.Controls.Add(lblConfirm);
            pnlInput.Controls.Add(txtConfirm);
            pnlInput.Controls.Add(btnSave);
            pnlInput.Controls.Add(btnBack);

            btnSave.Click += (s, e) =>
            {
                if (!PasswordManager.VerifyPassword(txtCurrent.Text))
                {
                    MessageBox.Show(Loc.T("كلمة السر الحالية غير صحيحة!", "Current password is incorrect!"), Loc.T("خطأ", "Error"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (string.IsNullOrEmpty(txtNew.Text))
                {
                    MessageBox.Show(Loc.T("يرجى إدخال كلمة السر الجديدة!", "Please enter the new password!"), Loc.T("تنبيه", "Warning"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
                if (txtNew.Text != txtConfirm.Text)
                {
                    MessageBox.Show(Loc.T("كلمتا السر غير متطابقتين!", "Passwords do not match!"), Loc.T("خطأ", "Error"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return;
                }
                if (PasswordManager.SetPassword(txtNew.Text))
                {
                    MessageBox.Show(Loc.T("تم تحديث كلمة السر بنجاح!", "Password updated successfully!"), Loc.T("نجاح", "Success"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    ShowControlView();
                }
            };

            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(btnLang);
            contentCard.Controls.Add(divider);
            contentCard.Controls.Add(pnlInput);
        }
        #endregion

        #region USB Storage Management (USBSTOR Registry + PnP Hardware Control)
        private const string UsbStorPath = @"SYSTEM\CurrentControlSet\Services\USBSTOR";

        private bool IsUsbStorageEnabled()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(UsbStorPath))
                {
                    if (key != null)
                    {
                        object val = key.GetValue("Start");
                        int startVal;
                        if (val != null && int.TryParse(val.ToString(), out startVal))
                        {
                            return startVal == 3; // 3 = Enabled, 4 = Disabled
                        }
                    }
                }
            }
            catch { }
            return true;
        }

        private void SetUsbStorageEnabled(bool enable)
        {
            try
            {
                if (enable)
                {
                    UsbHardwareManager.EnableAllUsbStorage();
                    SecurityLogger.LogEvent("USB_STORAGE_ENABLED",
                        Loc.T("تم فتح وتمكين منافذ الفلاشات", "USB Storage ports opened"));
                }
                else
                {
                    UsbHardwareManager.DisableAllUsbStorage();
                    SecurityLogger.LogEvent("USB_STORAGE_DISABLED",
                        Loc.T("تم قفل وحظر منافذ الفلاشات فوراً", "USB Storage ports blocked"));
                }

                string botToken, chatId;
                AlertNotifier.LoadTelegramConfig(out botToken, out chatId);
                if (!string.IsNullOrEmpty(botToken) && !string.IsNullOrEmpty(chatId))
                {
                    string alertMsg = enable
                        ? string.Format("🟢 [USB Shield] تم فتح منافذ الفلاشات (USB Ports Unlocked) على جهاز {0} في تمام {1:HH:mm:ss}", Environment.MachineName, DateTime.Now)
                        : string.Format("⛔ [USB Shield] تم قفل وحظر منافذ الفلاشات (USB Ports Blocked) على جهاز {0} في تمام {1:HH:mm:ss}", Environment.MachineName, DateTime.Now);
                    AlertNotifier.SendTelegramAlert(botToken, chatId, alertMsg);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(Loc.T("حدث خطأ أثناء تعديل المنافذ:\n", "Error modifying ports:\n") + ex.Message, Loc.T("خطأ في الصلاحيات", "Permission Error"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnToggleUsb_Click(object sender, EventArgs e)
        {
            bool currentState = IsUsbStorageEnabled();
            SetUsbStorageEnabled(!currentState);
            RefreshAllStatus();
        }
        #endregion

        #region USB Write-Protect Management (StorageDevicePolicies)
        private const string StoragePoliciesPath = @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";

        private bool IsWriteProtectEnabled()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(StoragePoliciesPath))
                {
                    if (key != null)
                    {
                        object val = key.GetValue("WriteProtect");
                        int wpVal;
                        if (val != null && int.TryParse(val.ToString(), out wpVal))
                        {
                            return wpVal == 1; // 1 = Read-only, 0 = Normal
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private void SetWriteProtectEnabled(bool enable)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(StoragePoliciesPath))
                {
                    if (key != null)
                    {
                        key.SetValue("WriteProtect", enable ? 1 : 0, RegistryValueKind.DWord);
                        
                        // Trigger rescan in background so write protection policy is applied
                        ThreadPool.QueueUserWorkItem(delegate
                        {
                            try
                            {
                                ProcessStartInfo psi = new ProcessStartInfo("pnputil.exe", "/scan-devices")
                                {
                                    CreateNoWindow = true,
                                    UseShellExecute = false,
                                    WindowStyle = ProcessWindowStyle.Hidden
                                };
                                using (Process p = Process.Start(psi))
                                {
                                    if (p != null) p.WaitForExit(2000);
                                }
                            }
                            catch { }
                        });

                        SecurityLogger.LogEvent(enable ? "WRITE_PROTECT_ENABLED" : "WRITE_PROTECT_DISABLED",
                            Loc.T(enable ? "تم تفعيل وضع الحماية من النسخ (قراءة فقط)" : "تم تعطيل وضع الحماية من النسخ (عادي)",
                                  enable ? "Write protection enabled (read-only)" : "Write protection disabled"));

                        string botToken, chatId;
                        AlertNotifier.LoadTelegramConfig(out botToken, out chatId);
                        if (!string.IsNullOrEmpty(botToken) && !string.IsNullOrEmpty(chatId))
                        {
                            string alertMsg = enable
                                ? string.Format("🛡️ [USB Shield] تم تفعيل الحماية من النسخ (Read-Only Mode) على جهاز {0} في تمام {1:HH:mm:ss}", Environment.MachineName, DateTime.Now)
                                : string.Format("✍️ [USB Shield] تم تعطيل الحماية من النسخ (السماح بالكتابة) على جهاز {0} في تمام {1:HH:mm:ss}", Environment.MachineName, DateTime.Now);
                            AlertNotifier.SendTelegramAlert(botToken, chatId, alertMsg);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(Loc.T("حدث خطأ أثناء تعديل وضع الحماية من الكتابة:\n", "Error modifying write protection:\n") + ex.Message, Loc.T("خطأ", "Error"), MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void BtnToggleWriteProtect_Click(object sender, EventArgs e)
        {
            bool currentState = IsWriteProtectEnabled();
            SetWriteProtectEnabled(!currentState);
            RefreshAllStatus();
        }
        #endregion

        #region Auto-Start Toggle
        private void BtnToggleAutoStart_Click(object sender, EventArgs e)
        {
            bool currentAutoStart = AutoStartManager.IsAutoStartEnabled();
            AutoStartManager.SetAutoStart(!currentAutoStart);
            SecurityLogger.LogEvent(!currentAutoStart ? "AUTOSTART_ENABLED" : "AUTOSTART_DISABLED",
                Loc.T(!currentAutoStart ? "تم تفعيل بدء التشغيل التلقائي مع الويندوز" : "تم تعطيل بدء التشغيل التلقائي",
                      !currentAutoStart ? "Auto-start enabled" : "Auto-start disabled"));
            RefreshAllStatus();
        }
        #endregion

        private void RefreshAllStatus()
        {
            if (lblUsbStatus == null || btnToggleUsb == null) return;

            // 1. USB Storage
            bool usbEnabled = IsUsbStorageEnabled();
            if (usbEnabled)
            {
                lblUsbStatus.Text = Loc.T("💾 منافذ الفلاشات:  🟢 مفتوحة ومتاحة", "💾 Flash Ports:  🟢 Open & Enabled");
                btnToggleUsb.Text = Loc.T("⛔ قفل وتعطيل منافذ USB", "⛔ Block & Disable USB Ports");
                btnToggleUsb.BackColor = Color.FromArgb(185, 28, 28);
                btnToggleUsb.ForeColor = Color.White;
            }
            else
            {
                lblUsbStatus.Text = Loc.T("💾 منافذ الفلاشات:  🔴 مقفلة ومحظورة", "💾 Flash Ports:  🔴 Locked & Blocked");
                btnToggleUsb.Text = Loc.T("🔓 فتح وتمكين منافذ USB", "🔓 Unlock & Enable USB Ports");
                btnToggleUsb.BackColor = ClrAccentGreen;
                btnToggleUsb.ForeColor = Color.White;
            }

            // 2. Write-Protect
            bool wpEnabled = IsWriteProtectEnabled();
            if (wpEnabled)
            {
                lblWriteProtectStatus.Text = Loc.T("✍️ الحماية من النسخ:  🛡️ قراءة فقط", "✍️ Copy Protection:  🛡️ Read-Only");
                btnToggleWriteProtect.Text = Loc.T("✍️ السماح بالكتابة والنسخ", "✍️ Allow Write & Copy");
                btnToggleWriteProtect.BackColor = ClrAccentBlue;
                btnToggleWriteProtect.ForeColor = Color.White;
            }
            else
            {
                lblWriteProtectStatus.Text = Loc.T("✍️ الحماية من النسخ:  ✍️ القراءة والكتابة مسموحة", "✍️ Copy Protection:  ✍️ Read & Write Allowed");
                btnToggleWriteProtect.Text = Loc.T("🛡️ تفعيل القراءة فقط (حظر النسخ)", "🛡️ Enable Read-Only (Block Copy)");
                btnToggleWriteProtect.BackColor = ClrAccentOrange;
                btnToggleWriteProtect.ForeColor = Color.White;
            }

            // 3. Auto-Start
            if (lblAutoStartStatus != null && btnToggleAutoStart != null)
            {
                bool autoStart = AutoStartManager.IsAutoStartEnabled();
                if (autoStart)
                {
                    lblAutoStartStatus.Text = Loc.T("🔄 الإقلاع مع الويندوز:  🟢 مفعّل", "🔄 Windows Startup:  🟢 Enabled");
                    btnToggleAutoStart.Text = Loc.T("🛑 تعطيل التشغيل التلقائي", "🛑 Disable Auto-Start");
                    btnToggleAutoStart.BackColor = ClrBtnDefault;
                    btnToggleAutoStart.ForeColor = Color.White;
                }
                else
                {
                    lblAutoStartStatus.Text = Loc.T("🔄 الإقلاع مع الويندوز:  ⚪ معطّل", "🔄 Windows Startup:  ⚪ Disabled");
                    btnToggleAutoStart.Text = Loc.T("⚡ تفعيل التشغيل التلقائي", "⚡ Enable Auto-Start");
                    btnToggleAutoStart.BackColor = ClrAccentGreen;
                    btnToggleAutoStart.ForeColor = Color.White;
                }
            }
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);
            if (m.Msg == WM_DEVICECHANGE && lblLiveIndicator != null)
            {
                int eventType = m.WParam.ToInt32();
                if (eventType == DBT_DEVICEARRIVAL)
                {
                    string time = DateTime.Now.ToString("HH:mm:ss");

                    if (WhitelistManager.IsWhitelistModeEnabled())
                    {
                        // Run whitelist enforcement in background thread
                        ThreadPool.QueueUserWorkItem(delegate
                        {
                            Thread.Sleep(600); // Give Windows time to register device
                            UsbHardwareManager.EnforceWhitelist();

                            try
                            {
                                this.BeginInvoke((MethodInvoker)delegate
                                {
                                    var connected = UsbHardwareManager.GetActiveUsbStorageDevices();
                                    var whitelisted = WhitelistManager.GetWhitelistedDevices();
                                    bool hasAllowed = false;
                                    foreach (var d in connected)
                                    {
                                        foreach (var w in whitelisted)
                                        {
                                            if (d.InstanceId.IndexOf(w.DeviceId, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                w.DeviceId.IndexOf(d.InstanceId, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                d.Description.IndexOf(w.Name, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                                w.Name.IndexOf(d.Description, StringComparison.OrdinalIgnoreCase) >= 0)
                                            {
                                                hasAllowed = true;
                                                break;
                                            }
                                        }
                                    }

                                    if (hasAllowed)
                                    {
                                        lblLiveIndicator.Text = Loc.T("🟢 [" + time + "] تم السماح بفلاشة مصرح بها", "🟢 [" + time + "] Whitelisted USB allowed");
                                        lblLiveIndicator.ForeColor = Color.FromArgb(74, 222, 128);
                                        SecurityLogger.LogEvent("WHITELIST_DEVICE_ALLOWED", Loc.T("تم تنشيط فلاشة مصرح بها من القائمة البيضاء", "Whitelisted USB activated"));
                                    }
                                    else
                                    {
                                        lblLiveIndicator.Text = Loc.T("⛔ [" + time + "] تم حظر فلاشة غير مصرح بها", "⛔ [" + time + "] Blocked unauthorized USB");
                                        lblLiveIndicator.ForeColor = ClrAccentRed;
                                        SecurityLogger.LogEvent("UNAUTHORIZED_DEVICE_BLOCKED", Loc.T("تم حظر جهاز USB غير مدرج في القائمة البيضاء", "Unauthorized USB blocked by Whitelist"));
                                    }
                                    RefreshAllStatus();
                                });
                            }
                            catch { }
                        });
                    }
                    else
                    {
                        lblLiveIndicator.Text = Loc.T("🔌 [" + time + "] تم توصيل جهاز USB", "🔌 [" + time + "] USB Device Connected");
                        lblLiveIndicator.ForeColor = Color.FromArgb(74, 222, 128);
                        SecurityLogger.LogEvent("DEVICE_CONNECTED", Loc.T("تم توصيل جهاز USB جديد بالجهاز", "USB Device attached"));
                    }

                    string botToken, chatId;
                    AlertNotifier.LoadTelegramConfig(out botToken, out chatId);
                    if (!string.IsNullOrEmpty(botToken) && !string.IsNullOrEmpty(chatId))
                    {
                        string alertText = WhitelistManager.IsWhitelistModeEnabled()
                            ? string.Format("🛡️ [USB Shield - القائمة البيضاء] تم توصيل جهاز USB على {0} في تمام {1}. تم فحص القائمة البيضاء.", Environment.MachineName, time)
                            : string.Format("🔌 [USB Shield] تم توصيل جهاز USB في الجهاز {0} في تمام الساعة: {1}", Environment.MachineName, time);
                        AlertNotifier.SendTelegramAlert(botToken, chatId, alertText);
                    }
                }
                else if (eventType == DBT_DEVICEREMOVECOMPLETE)
                {
                    string time = DateTime.Now.ToString("HH:mm:ss");
                    lblLiveIndicator.Text = Loc.T("⏏️ [" + time + "] تم فصل جهاز USB", "⏏️ [" + time + "] USB Device Unplugged");
                    lblLiveIndicator.ForeColor = ClrAccentRed;
                    SecurityLogger.LogEvent("DEVICE_DISCONNECTED", Loc.T("تم فصل جهاز USB من المنفذ", "USB Device removed"));
                }
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
                this.Hide();
                if (trayIcon != null)
                {
                    trayIcon.ShowBalloonTip(
                        2000,
                        Loc.T("درع منافذ USB", "USB Port Shield"),
                        Loc.T("البرنامج يعمل في الخلفية ويحمي منافذك باستمرار.", "Application is running in background to protect ports continuously."),
                        ToolTipIcon.Info
                    );
                }
            }
            else
            {
                if (trayIcon != null)
                {
                    trayIcon.Visible = false;
                    trayIcon.Dispose();
                }
                base.OnFormClosing(e);
            }
        }
    }
    #endregion
}
