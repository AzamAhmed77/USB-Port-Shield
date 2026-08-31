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
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                // 1. Check all Removable & Fixed drives (except system drive C:)
                foreach (DriveInfo drive in DriveInfo.GetDrives())
                {
                    try
                    {
                        if (drive.IsReady && !drive.Name.StartsWith("C:", StringComparison.OrdinalIgnoreCase))
                        {
                            string label = string.IsNullOrEmpty(drive.VolumeLabel) ? Loc.T("قرص USB", "USB Disk") : drive.VolumeLabel;
                            double sizeGb = Math.Round((double)drive.TotalSize / (1024 * 1024 * 1024), 1);
                            string item = string.Format("{0} ({1}) - {2} GB", label, drive.Name.TrimEnd('\\'), sizeGb);
                            if (!seen.Contains(item))
                            {
                                seen.Add(item);
                                drives.Add(item);
                            }
                        }
                    }
                    catch { }
                }

                // 2. Scan Registry USBSTOR history for plugged hardware IDs if DriveInfo is blocked
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
                                                string displayName = !string.IsNullOrEmpty(friendlyName) ? friendlyName : subKeyName.Replace("Disk&Ven_", "").Replace("&Prod_", " ").Replace("&Rev_", " ");
                                                string item = string.Format("💾 {0} [ID: {1}]", displayName, serial.Length > 8 ? serial.Substring(0, 8) + "..." : serial);
                                                if (!seen.Contains(item))
                                                {
                                                    seen.Add(item);
                                                    drives.Add(item);
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
                    lblTimerStatus.ForeColor = Color.FromArgb(251, 191, 36);
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
            this.Size = new Size(540, 560);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = true;
            this.BackColor = Color.FromArgb(15, 23, 42);
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
                Color.FromArgb(11, 15, 25),
                Color.FromArgb(26, 36, 56),
                45F))
            {
                e.Graphics.FillRectangle(brush, this.ClientRectangle);
            }

            using (Pen borderPen = new Pen(Color.FromArgb(45, 55, 75), 1))
            {
                e.Graphics.DrawRectangle(borderPen, 0, 0, this.ClientSize.Width - 1, this.ClientSize.Height - 1);
            }
        }

        private void InitCardContainer()
        {
            contentCard = new Panel
            {
                Location = new Point(18, 12),
                Size = new Size(488, 495),
                BackColor = Color.FromArgb(30, 41, 59),
                Padding = new Padding(12)
            };
            this.Controls.Add(contentCard);
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
                Text = Loc.IsArabic ? "🌐 English" : "🌐 العربية",
                Size = new Size(90, 26),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.FromArgb(226, 232, 240),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnLang.FlatAppearance.BorderSize = 0;
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

            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(15, 12) : new Point(340, 12);

            PictureBox picLogo = CreateLogoHeader(48);
            picLogo.Location = Loc.IsArabic ? new Point(380, 10) : new Point(15, 10);

            Label lblTitle = new Label
            {
                Text = Loc.T("🔐 التطبيق محمي بكلمة سر", "🔐 Application is Locked"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 12F, FontStyle.Bold),
                Location = Loc.IsArabic ? new Point(115, 15) : new Point(70, 15),
                Size = new Size(260, 28),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblDesc = new Label
            {
                Text = Loc.T("أدخل كلمة السر الرئيسية للوصول للتحكم بمنافذ USB:", "Enter master password to access USB port controls:"),
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 9F),
                Location = new Point(15, 75),
                Size = new Size(418, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            TextBox txtPassword = new TextBox
            {
                Location = new Point(15, 110),
                Size = new Size(418, 30),
                PasswordChar = '●',
                BackColor = Color.FromArgb(15, 23, 42),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 11F)
            };

            Label lblError = new Label
            {
                Text = "",
                ForeColor = Color.FromArgb(248, 113, 113),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(15, 155),
                Size = new Size(418, 22),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Button btnUnlock = new Button
            {
                Text = Loc.T("فتح القفل 🔓", "Unlock 🔓"),
                Location = new Point(15, 195),
                Size = new Size(418, 45),
                BackColor = Color.FromArgb(16, 185, 129),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnUnlock.FlatAppearance.BorderSize = 0;

            Button btnExit = new Button
            {
                Text = Loc.T("خروج", "Exit"),
                Location = new Point(15, 255),
                Size = new Size(418, 38),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.FromArgb(226, 232, 240),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F),
                Cursor = Cursors.Hand
            };
            btnExit.FlatAppearance.BorderSize = 0;
            btnExit.Click += (s, e) => ExitApplication();

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

            contentCard.Controls.Add(picLogo);
            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(btnLang);
            contentCard.Controls.Add(lblDesc);
            contentCard.Controls.Add(txtPassword);
            contentCard.Controls.Add(lblError);
            contentCard.Controls.Add(btnUnlock);
            contentCard.Controls.Add(btnExit);

            this.AcceptButton = btnUnlock;
            txtPassword.Focus();
        }
        #endregion

        #region View 2: إعداد كلمة السر لأول مرة
        private void ShowSetupPasswordView()
        {
            activeView = CurrentViewType.SetupPassword;
            contentCard.Controls.Clear();

            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(15, 10) : new Point(340, 10);

            PictureBox picLogo = CreateLogoHeader(42);
            picLogo.Location = Loc.IsArabic ? new Point(385, 8) : new Point(15, 8);

            Label lblTitle = new Label
            {
                Text = Loc.T("🔒 تعيين كلمة سر رئيسية", "🔒 Set Master Password"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 11.5F, FontStyle.Bold),
                Location = Loc.IsArabic ? new Point(115, 12) : new Point(65, 12),
                Size = new Size(260, 26),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblPass = new Label
            {
                Text = Loc.T("كلمة السر الجديدة:", "New Password:"),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(15, 60),
                Size = new Size(418, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };
            TextBox txtNew = new TextBox { Location = new Point(15, 85), Size = new Size(418, 26), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Label lblConf = new Label
            {
                Text = Loc.T("تأكيد كلمة السر:", "Confirm Password:"),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(15, 125),
                Size = new Size(418, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };
            TextBox txtConf = new TextBox { Location = new Point(15, 150), Size = new Size(418, 26), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Label lblErr = new Label
            {
                Text = "",
                ForeColor = Color.FromArgb(248, 113, 113),
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Location = new Point(15, 185),
                Size = new Size(418, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Button btnSave = new Button
            {
                Text = Loc.T("حفظ ومتابعة ✔", "Save & Continue ✔"),
                Location = new Point(15, 215),
                Size = new Size(418, 42),
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 10F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnSave.FlatAppearance.BorderSize = 0;

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

            contentCard.Controls.Add(picLogo);
            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(btnLang);
            contentCard.Controls.Add(lblPass);
            contentCard.Controls.Add(txtNew);
            contentCard.Controls.Add(lblConf);
            contentCard.Controls.Add(txtConf);
            contentCard.Controls.Add(lblErr);
            contentCard.Controls.Add(btnSave);

            this.AcceptButton = btnSave;
        }
        #endregion

        #region View 3: لوحة التحكم الرئيسية الكاملة
        private void ShowControlView()
        {
            activeView = CurrentViewType.Control;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 24; // 464

            // 1. الشريط العلوي المتناسق
            PictureBox picLogo = CreateLogoHeader(28);
            picLogo.Location = Loc.IsArabic ? new Point(cardW - 28, 8) : new Point(8, 8);

            Label lblTitle = new Label
            {
                Text = Loc.T("درع حماية USB", "USB Shield Pro"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
                Location = Loc.IsArabic ? new Point(cardW - 145, 9) : new Point(40, 9),
                Size = new Size(110, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            // أزرار شريط الأدوات العلوية السريعة
            Button btnLang = CreateLangSwitchButton();
            btnLang.Size = new Size(58, 26);
            btnLang.Font = new Font("Segoe UI", 8F, FontStyle.Bold);
            btnLang.Location = Loc.IsArabic ? new Point(cardW - 210, 7) : new Point(155, 7);

            Button btnLogs = new Button
            {
                Text = Loc.T("📋 السجل", "📋 Logs"),
                Size = new Size(62, 26),
                Location = Loc.IsArabic ? new Point(cardW - 276, 7) : new Point(217, 7),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnLogs.FlatAppearance.BorderSize = 0;
            btnLogs.Click += (s, e) => ShowActivityLogsView();

            Button btnTimer = new Button
            {
                Text = Loc.T("⏳ مؤقت", "⏳ Timer"),
                Size = new Size(60, 26),
                Location = Loc.IsArabic ? new Point(cardW - 340, 7) : new Point(283, 7),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnTimer.FlatAppearance.BorderSize = 0;
            btnTimer.Click += (s, e) => ShowAutoLockTimerView();

            Button btnPass = new Button
            {
                Text = Loc.T("🔑", "🔑"),
                Size = new Size(30, 26),
                Location = Loc.IsArabic ? new Point(42, 7) : new Point(347, 7),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnPass.FlatAppearance.BorderSize = 0;
            btnPass.Click += (s, e) => ShowChangePasswordView();

            Button btnLock = new Button
            {
                Text = Loc.T("🔒", "🔒"),
                Size = new Size(30, 26),
                Location = Loc.IsArabic ? new Point(8, 7) : new Point(381, 7),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnLock.FlatAppearance.BorderSize = 0;
            btnLock.Click += (s, e) => ShowUnlockView();

            // 2. حالة المؤقت إن وجد
            lblTimerStatus = new Label
            {
                Text = AutoLockTimerManager.IsTimerRunning
                    ? Loc.T(string.Format("⏳ المؤقت نشط: يغلق تلقائياً بعد {0:D2}:{1:D2}", AutoLockTimerManager.RemainingSeconds / 60, AutoLockTimerManager.RemainingSeconds % 60), "⏳ Auto-locking in active timer")
                    : "",
                ForeColor = Color.FromArgb(251, 191, 36),
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Location = new Point(8, 38),
                Size = new Size(cardW, 18),
                TextAlign = ContentAlignment.MiddleCenter
            };

            // 3. قسم منافذ فلاشات USB
            lblUsbStatus = new Label
            {
                Text = Loc.T("💾 منافذ الفلاشات: جاري الفحص...", "💾 USB Storage: Checking..."),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(8, 60),
                Size = new Size(cardW, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            btnToggleUsb = new Button
            {
                Text = Loc.T("تغيير الحالة", "Toggle Status"),
                Location = new Point(8, 80),
                Size = new Size(cardW, 36),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnToggleUsb.FlatAppearance.BorderSize = 0;
            btnToggleUsb.Click += BtnToggleUsb_Click;

            // 4. قسم وضع الحماية من النسخ (Write-Protect)
            lblWriteProtectStatus = new Label
            {
                Text = Loc.T("✍️ الحماية من النسخ: جاري الفحص...", "✍️ Write Protection: Checking..."),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(8, 122),
                Size = new Size(cardW, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            btnToggleWriteProtect = new Button
            {
                Text = Loc.T("تغيير وضع الحماية", "Toggle Protection"),
                Location = new Point(8, 142),
                Size = new Size(cardW, 36),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnToggleWriteProtect.FlatAppearance.BorderSize = 0;
            btnToggleWriteProtect.Click += BtnToggleWriteProtect_Click;

            // 5. قسم التشغيل التلقائي مع إقلاع الجهاز
            lblAutoStartStatus = new Label
            {
                Text = Loc.T("🔄 الحماية مع إقلاع الويندوز: جاري الفحص...", "🔄 Startup Protection: Checking..."),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(8, 184),
                Size = new Size(cardW, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            btnToggleAutoStart = new Button
            {
                Text = Loc.T("تبديل وضع الإقلاع", "Toggle Startup Mode"),
                Location = new Point(8, 204),
                Size = new Size(cardW, 36),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnToggleAutoStart.FlatAppearance.BorderSize = 0;
            btnToggleAutoStart.Click += BtnToggleAutoStart_Click;

            // 6. صف أزرار الخدمات الإضافية (القائمة البيضاء + إعدادات تيليجرام)
            int halfW = (cardW - 8) / 2;
            Button btnWhitelist = new Button
            {
                Text = Loc.T("🛡️ القائمة البيضاء (الأجهزة المصرحة)", "🛡️ Device Whitelist"),
                Location = Loc.IsArabic ? new Point(halfW + 16, 248) : new Point(8, 248),
                Size = new Size(halfW, 36),
                BackColor = Color.FromArgb(16, 185, 129),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnWhitelist.FlatAppearance.BorderSize = 0;
            btnWhitelist.Click += (s, e) => ShowWhitelistView();

            Button btnTgAlerts = new Button
            {
                Text = Loc.T("🔔 إعدادات بوت Telegram", "🔔 Telegram Alerts"),
                Location = Loc.IsArabic ? new Point(8, 248) : new Point(halfW + 16, 248),
                Size = new Size(halfW, 36),
                BackColor = Color.FromArgb(14, 116, 144),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnTgAlerts.FlatAppearance.BorderSize = 0;
            btnTgAlerts.Click += (s, e) => ShowTelegramSettingsView();

            // 7. زر إيقاف الخدمة والخروج تماماً
            Button btnStopService = new Button
            {
                Text = Loc.T("🛑 إيقاف الحماية والخروج تماماً", "🛑 Stop Protection & Exit Completely"),
                Location = new Point(8, 292),
                Size = new Size(cardW, 36),
                BackColor = Color.FromArgb(185, 28, 28),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnStopService.FlatAppearance.BorderSize = 0;
            btnStopService.Click += (s, e) => ExitApplication();

            // 8. مؤشر المراقبة الحية
            lblLiveIndicator = new Label
            {
                Text = Loc.T("🟢 درع الحماية نشط ومستمر (يكتشف الأجهزة تلقائياً)", "🟢 Protection Active & Persistent (Auto-detects Devices)"),
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(8, 336),
                Size = new Size(cardW, 20),
                TextAlign = ContentAlignment.MiddleCenter
            };

            contentCard.Controls.Add(picLogo);
            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(btnLang);
            contentCard.Controls.Add(btnLogs);
            contentCard.Controls.Add(btnTimer);
            contentCard.Controls.Add(btnPass);
            contentCard.Controls.Add(btnLock);
            contentCard.Controls.Add(lblTimerStatus);
            contentCard.Controls.Add(lblUsbStatus);
            contentCard.Controls.Add(btnToggleUsb);
            contentCard.Controls.Add(lblWriteProtectStatus);
            contentCard.Controls.Add(btnToggleWriteProtect);
            contentCard.Controls.Add(lblAutoStartStatus);
            contentCard.Controls.Add(btnToggleAutoStart);
            contentCard.Controls.Add(btnWhitelist);
            contentCard.Controls.Add(btnTgAlerts);
            contentCard.Controls.Add(btnStopService);
            contentCard.Controls.Add(lblLiveIndicator);

            RefreshAllStatus();
        }
        #endregion

        #region View 4: شاشة سجل الأحداث الأمنية (Activity Logs)
        private void ShowActivityLogsView()
        {
            activeView = CurrentViewType.ActivityLogs;
            contentCard.Controls.Clear();

            Label lblTitle = new Label
            {
                Text = Loc.T("📋 سجل النشاط والأحداث الأمنية", "📋 Security Activity & Event Logs"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                Location = new Point(12, 10),
                Size = new Size(424, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            ListBox listLogs = new ListBox
            {
                Location = new Point(12, 40),
                Size = new Size(424, 250),
                BackColor = Color.FromArgb(15, 23, 42),
                ForeColor = Color.FromArgb(148, 163, 184),
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

            Button btnExport = new Button
            {
                Text = Loc.T("💾 تصدير كملف", "💾 Export Log"),
                Location = Loc.IsArabic ? new Point(230, 300) : new Point(12, 300),
                Size = new Size(100, 32),
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnExport.FlatAppearance.BorderSize = 0;
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

            Button btnClear = new Button
            {
                Text = Loc.T("🗑️ مسح السجل", "🗑️ Clear"),
                Location = Loc.IsArabic ? new Point(120, 300) : new Point(120, 300),
                Size = new Size(100, 32),
                BackColor = Color.FromArgb(185, 28, 28),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnClear.FlatAppearance.BorderSize = 0;
            btnClear.Click += (s, e) =>
            {
                SecurityLogger.ClearLogs();
                ShowActivityLogsView();
            };

            Button btnBack = new Button
            {
                Text = Loc.T("رجوع ↩", "Back ↩"),
                Location = Loc.IsArabic ? new Point(12, 300) : new Point(335, 300),
                Size = new Size(95, 32),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9F),
                Cursor = Cursors.Hand
            };
            btnBack.FlatAppearance.BorderSize = 0;
            btnBack.Click += (s, e) => ShowControlView();

            contentCard.Controls.Add(lblTitle);
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

            Label lblTitle = new Label
            {
                Text = Loc.T("⏳ مؤقت الفتح المؤقت والقفل الذاتي", "⏳ Temporary Unlock & Auto-Lock Timer"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                Location = new Point(12, 15),
                Size = new Size(424, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblDesc = new Label
            {
                Text = Loc.T(
                    "يمكنك فتح المنافذ لفترة محددة، وسيقوم البرنامج بقفلها تلقائياً عند انتهاء الوقت لحماية الجهاز في حال نسيانه:",
                    "Open USB ports temporarily; the app will automatically lock them when time expires:"
                ),
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 9F),
                Location = new Point(12, 45),
                Size = new Size(424, 40),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            // أزرار مدد المؤقت
            int[] durations = new int[] { 5, 15, 30, 60 };
            string[] durLabels = new string[] {
                Loc.T("⏱️ 5 دقائق", "⏱️ 5 Minutes"),
                Loc.T("⏱️ 15 دقيقة", "⏱️ 15 Minutes"),
                Loc.T("⏱️ 30 دقيقة", "⏱️ 30 Minutes"),
                Loc.T("⏱️ 1 ساعة كاملة", "⏱️ 1 Hour")
            };

            for (int i = 0; i < durations.Length; i++)
            {
                int min = durations[i];
                Button btnPreset = new Button
                {
                    Text = durLabels[i],
                    Location = new Point(12, 95 + (i * 42)),
                    Size = new Size(424, 36),
                    BackColor = Color.FromArgb(30, 58, 138),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat,
                    Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                    Cursor = Cursors.Hand
                };
                btnPreset.FlatAppearance.BorderSize = 0;
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
                Button btnCancelTimer = new Button
                {
                    Text = Loc.T("🛑 إيقاف المؤقت وإلغاؤه الآن", "🛑 Cancel & Stop Timer Now"),
                    Location = new Point(12, 275),
                    Size = new Size(424, 36),
                    BackColor = Color.FromArgb(185, 28, 28),
                    ForeColor = Color.White,
                    FlatStyle = FlatStyle.Flat,
                    Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                    Cursor = Cursors.Hand
                };
                btnCancelTimer.FlatAppearance.BorderSize = 0;
                btnCancelTimer.Click += (s, e) =>
                {
                    AutoLockTimerManager.StopTimer();
                    MessageBox.Show(Loc.T("تم إيقاف المؤقت بنجاح!", "Timer cancelled!"), Loc.T("إلغاء المؤقت", "Timer Cancelled"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    ShowControlView();
                };
                contentCard.Controls.Add(btnCancelTimer);
            }

            Button btnBack = new Button
            {
                Text = Loc.T("رجوع", "Back"),
                Location = new Point(12, 320),
                Size = new Size(424, 34),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9F),
                Cursor = Cursors.Hand
            };
            btnBack.FlatAppearance.BorderSize = 0;
            btnBack.Click += (s, e) => ShowControlView();

            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(lblDesc);
            contentCard.Controls.Add(btnBack);
        }
        #endregion

        #region View 6: شاشة إعدادات تنبيهات تيليجرام
        private void ShowTelegramSettingsView()
        {
            activeView = CurrentViewType.TelegramSettings;
            contentCard.Controls.Clear();

            Label lblTitle = new Label
            {
                Text = Loc.T("🔔 إعدادات تنبيهات Telegram الفورية", "🔔 Telegram Security Alerts Settings"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                Location = new Point(12, 12),
                Size = new Size(424, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblDesc = new Label
            {
                Text = Loc.T(
                    "يمكنك ربط البرنامج ببوت Telegram ليصلك إشعار فوري عند إدخال فلاشة غريبة أو محاولة فتح البرنامج بكلمة سر خاطئة:",
                    "Connect to Telegram bot to receive instant alerts when a USB is plugged in or invalid password is used:"
                ),
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(12, 40),
                Size = new Size(424, 36),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            string curToken, curChatId;
            AlertNotifier.LoadTelegramConfig(out curToken, out curChatId);

            Label lblToken = new Label { Text = Loc.T("رمز البوت (Bot Token):", "Bot Token:"), ForeColor = Color.FromArgb(226, 232, 240), Location = new Point(12, 85), Size = new Size(424, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtToken = new TextBox { Text = curToken, Location = new Point(12, 105), Size = new Size(424, 24), BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Label lblChat = new Label { Text = Loc.T("معرف المحادثة (Chat ID):", "Chat ID:"), ForeColor = Color.FromArgb(226, 232, 240), Location = new Point(12, 140), Size = new Size(424, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtChat = new TextBox { Text = curChatId, Location = new Point(12, 160), Size = new Size(424, 24), BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Button btnTest = new Button
            {
                Text = Loc.T("📨 إرسال تنبيه تجريبي", "📨 Send Test Alert"),
                Location = new Point(12, 200),
                Size = new Size(424, 34),
                BackColor = Color.FromArgb(14, 116, 144),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnTest.FlatAppearance.BorderSize = 0;
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

            Button btnSave = new Button
            {
                Text = Loc.T("حفظ الإعدادات", "Save Settings"),
                Location = Loc.IsArabic ? new Point(12, 245) : new Point(12, 245),
                Size = new Size(210, 36),
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnSave.FlatAppearance.BorderSize = 0;
            btnSave.Click += (s, e) =>
            {
                AlertNotifier.SaveTelegramConfig(txtToken.Text, txtChat.Text);
                MessageBox.Show(Loc.T("تم حفظ إعدادات التنبيهات بنجاح!", "Settings saved successfully!"), Loc.T("نجاح", "Success"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                ShowControlView();
            };

            Button btnBack = new Button
            {
                Text = Loc.T("رجوع", "Back"),
                Location = Loc.IsArabic ? new Point(230, 245) : new Point(230, 245),
                Size = new Size(206, 36),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F),
                Cursor = Cursors.Hand
            };
            btnBack.FlatAppearance.BorderSize = 0;
            btnBack.Click += (s, e) => ShowControlView();

            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(lblDesc);
            contentCard.Controls.Add(lblToken);
            contentCard.Controls.Add(txtToken);
            contentCard.Controls.Add(lblChat);
            contentCard.Controls.Add(txtChat);
            contentCard.Controls.Add(btnTest);
            contentCard.Controls.Add(btnSave);
            contentCard.Controls.Add(btnBack);
        }
        #endregion

        #region View 8: شاشة إدارة القائمة البيضاء للأجهزة المصرحة
        private void ShowWhitelistView()
        {
            activeView = CurrentViewType.Whitelist;
            contentCard.Controls.Clear();

            int cardW = contentCard.Width - 24;

            Label lblTitle = new Label
            {
                Text = Loc.T("🛡️ القائمة البيضاء (الأجهزة والفلاشات المصرح بها)", "🛡️ Authorized Devices Whitelist"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                Location = new Point(8, 8),
                Size = new Size(cardW, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            bool isWhitelistEnabled = WhitelistManager.IsWhitelistModeEnabled();
            CheckBox chkEnableWhitelist = new CheckBox
            {
                Text = Loc.T("تفعيل وضع حظر جميع الفلاشات عدا المصرح بها فقط", "Enforce Whitelist: Block all devices except authorized"),
                Checked = isWhitelistEnabled,
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(8, 34),
                Size = new Size(cardW, 24),
                Cursor = Cursors.Hand
            };
            chkEnableWhitelist.CheckedChanged += (s, e) =>
            {
                WhitelistManager.SetWhitelistModeEnabled(chkEnableWhitelist.Checked);
                SecurityLogger.LogEvent(chkEnableWhitelist.Checked ? "WHITELIST_MODE_ENABLED" : "WHITELIST_MODE_DISABLED",
                    Loc.T(chkEnableWhitelist.Checked ? "تم تفعيل حظر الفلاشات غير المصرح بها" : "تم تعطيل وضع القائمة البيضاء",
                          chkEnableWhitelist.Checked ? "Whitelist mode enforced" : "Whitelist mode disabled"));
            };

            // 1. قسم الفلاشات المتصلة حالياً بالجهاز
            Label lblConnectedTitle = new Label
            {
                Text = Loc.T("🔌 الفلاشات المتصلة حالياً بالجهاز (اختر للإضافة الفورية):", "🔌 Currently Connected USB Drives (Select to Add):"),
                ForeColor = Color.FromArgb(74, 222, 128),
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Location = new Point(8, 62),
                Size = new Size(cardW, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            ComboBox cmbConnectedDrives = new ComboBox
            {
                Location = new Point(8, 82),
                Size = new Size(cardW - 130, 26),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(15, 23, 42),
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9F)
            };

            Button btnRefreshDrives = new Button
            {
                Text = Loc.T("🔄 فحص", "🔄 Scan"),
                Location = Loc.IsArabic ? new Point(cardW - 120, 81) : new Point(cardW - 120, 81),
                Size = new Size(55, 27),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnRefreshDrives.FlatAppearance.BorderSize = 0;

            Button btnAddCurrent = new Button
            {
                Text = Loc.T("➕ تصريح", "➕ Allow"),
                Location = Loc.IsArabic ? new Point(cardW - 60, 81) : new Point(cardW - 60, 81),
                Size = new Size(60, 27),
                BackColor = Color.FromArgb(16, 185, 129),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnAddCurrent.FlatAppearance.BorderSize = 0;

            Action refreshConnectedDrives = () =>
            {
                cmbConnectedDrives.Items.Clear();
                var drives = WhitelistManager.GetConnectedUsbDrives();
                if (drives.Count == 0)
                {
                    cmbConnectedDrives.Items.Add(Loc.T("لا توجد فلاشات متصلة حالياً (أدخل الفلاشه واضغط فحص)", "No USB drives connected (Insert USB & click Scan)"));
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

            // 2. قائمة الأجهزة المصرح بها الحالية
            Label lblWhitelistTitle = new Label
            {
                Text = Loc.T("📋 قائمة الأجهزة المصرح لها بالعمل:", "📋 Allowed Whitelist Devices:"),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Location = new Point(8, 116),
                Size = new Size(cardW, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            ListBox listDevices = new ListBox
            {
                Location = new Point(8, 136),
                Size = new Size(cardW, 175),
                BackColor = Color.FromArgb(15, 23, 42),
                ForeColor = Color.FromArgb(226, 232, 240),
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9F)
            };

            Action refreshWhitelist = () =>
            {
                listDevices.Items.Clear();
                var devices = WhitelistManager.GetWhitelistedDevices();
                if (devices.Count == 0)
                {
                    listDevices.Items.Add(Loc.T("لا توجد أجهزة مضافة في القائمة البيضاء حتى الآن.", "No authorized devices added yet."));
                }
                else
                {
                    foreach (var d in devices)
                    {
                        listDevices.Items.Add(string.Format("🔹 {0} [{1}] ({2})", d.Name, d.DeviceId, d.AddedDate));
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
                        MessageBox.Show(Loc.T("تمت إضافة الفلاشة بنجاح إلى القائمة البيضاء المصرح بها!", "USB drive successfully authorized!"), Loc.T("نجاح", "Success"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            };

            // 3. إضافة يدوية
            Label lblAddDesc = new Label
            {
                Text = Loc.T("أو إضافة بالاسم يدوياً:", "Or Add Manually by Name:"),
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(8, 318),
                Size = new Size(cardW, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            TextBox txtDevName = new TextBox
            {
                Location = new Point(8, 338),
                Size = new Size(cardW - 110, 26),
                BackColor = Color.FromArgb(15, 23, 42),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 9.5F)
            };

            Button btnAddManual = new Button
            {
                Text = Loc.T("➕ إضافة", "➕ Add"),
                Location = Loc.IsArabic ? new Point(cardW - 100, 337) : new Point(cardW - 100, 337),
                Size = new Size(100, 28),
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnAddManual.FlatAppearance.BorderSize = 0;
            btnAddManual.Click += (s, e) =>
            {
                if (string.IsNullOrEmpty(txtDevName.Text.Trim())) return;
                string dev = txtDevName.Text.Trim();
                WhitelistManager.AddDevice(dev, dev);
                txtDevName.Clear();
                refreshWhitelist();
            };

            // 4. أزرار التحكم
            Button btnRemove = new Button
            {
                Text = Loc.T("🗑️ حذف الجهاز المحدد", "🗑️ Remove Selected"),
                Location = Loc.IsArabic ? new Point(8, 375) : new Point(8, 375),
                Size = new Size(220, 34),
                BackColor = Color.FromArgb(185, 28, 28),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnRemove.FlatAppearance.BorderSize = 0;
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

            Button btnBack = new Button
            {
                Text = Loc.T("رجوع", "Back"),
                Location = Loc.IsArabic ? new Point(236, 375) : new Point(236, 375),
                Size = new Size(cardW - 236, 34),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9F),
                Cursor = Cursors.Hand
            };
            btnBack.FlatAppearance.BorderSize = 0;
            btnBack.Click += (s, e) => ShowControlView();

            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(chkEnableWhitelist);
            contentCard.Controls.Add(lblConnectedTitle);
            contentCard.Controls.Add(cmbConnectedDrives);
            contentCard.Controls.Add(btnRefreshDrives);
            contentCard.Controls.Add(btnAddCurrent);
            contentCard.Controls.Add(lblWhitelistTitle);
            contentCard.Controls.Add(listDevices);
            contentCard.Controls.Add(lblAddDesc);
            contentCard.Controls.Add(txtDevName);
            contentCard.Controls.Add(btnAddManual);
            contentCard.Controls.Add(btnRemove);
            contentCard.Controls.Add(btnBack);
        }
        #endregion

        #region View 7: شاشة تغيير كلمة السر
        private void ShowChangePasswordView()
        {
            activeView = CurrentViewType.ChangePassword;
            contentCard.Controls.Clear();

            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(12, 10) : new Point(340, 10);

            PictureBox picLogo = CreateLogoHeader(38);
            picLogo.Location = Loc.IsArabic ? new Point(390, 8) : new Point(12, 8);

            Label lblTitle = new Label
            {
                Text = Loc.T("🔑 تغيير كلمة السر", "🔑 Change Password"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 11.5F, FontStyle.Bold),
                Location = Loc.IsArabic ? new Point(120, 12) : new Point(60, 12),
                Size = new Size(260, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblCur = new Label { Text = Loc.T("كلمة السر الحالية:", "Current Password:"), ForeColor = Color.FromArgb(226, 232, 240), Location = new Point(12, 48), Size = new Size(424, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtCurrent = new TextBox { Location = new Point(12, 70), Size = new Size(424, 24), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Label lblNew = new Label { Text = Loc.T("كلمة السر الجديدة:", "New Password:"), ForeColor = Color.FromArgb(226, 232, 240), Location = new Point(12, 105), Size = new Size(424, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtNew = new TextBox { Location = new Point(12, 128), Size = new Size(424, 24), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Label lblConf = new Label { Text = Loc.T("تأكيد كلمة السر الجديدة:", "Confirm New Password:"), ForeColor = Color.FromArgb(226, 232, 240), Location = new Point(12, 162), Size = new Size(424, 18), TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft };
            TextBox txtConf = new TextBox { Location = new Point(12, 185), Size = new Size(424, 24), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Button btnSave = new Button
            {
                Text = Loc.T("حفظ التغيير", "Save Change"),
                Location = Loc.IsArabic ? new Point(12, 230) : new Point(12, 230),
                Size = new Size(220, 38),
                BackColor = Color.FromArgb(37, 99, 235),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnSave.FlatAppearance.BorderSize = 0;

            Button btnBack = new Button
            {
                Text = Loc.T("رجوع", "Back"),
                Location = Loc.IsArabic ? new Point(240, 230) : new Point(240, 230),
                Size = new Size(196, 38),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F),
                Cursor = Cursors.Hand
            };
            btnBack.FlatAppearance.BorderSize = 0;
            btnBack.Click += (s, e) => ShowControlView();

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
                if (txtNew.Text != txtConf.Text)
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

            contentCard.Controls.Add(picLogo);
            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(btnLang);
            contentCard.Controls.Add(lblCur);
            contentCard.Controls.Add(txtCurrent);
            contentCard.Controls.Add(lblNew);
            contentCard.Controls.Add(txtNew);
            contentCard.Controls.Add(lblConf);
            contentCard.Controls.Add(txtConf);
            contentCard.Controls.Add(btnSave);
            contentCard.Controls.Add(btnBack);
        }
        #endregion

        #region USB Storage Management (USBSTOR)
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
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(UsbStorPath, true))
                {
                    if (key != null)
                    {
                        key.SetValue("Start", enable ? 3 : 4, RegistryValueKind.DWord);
                        SecurityLogger.LogEvent(enable ? "USB_STORAGE_ENABLED" : "USB_STORAGE_DISABLED",
                            Loc.T(enable ? "تم فتح وتمكين منافذ الفلاشات" : "تم قفل وحظر منافذ الفلاشات",
                                  enable ? "USB Storage ports opened" : "USB Storage ports blocked"));

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
                    else
                    {
                        MessageBox.Show(Loc.T("تعذر الوصول إلى مسار سجل USBSTOR!", "Cannot access USBSTOR registry path!"), Loc.T("خطأ", "Error"), MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(Loc.T("حدث خطأ أثناء تعديل السجل:\n", "Error modifying registry:\n") + ex.Message, Loc.T("خطأ في الصلاحيات", "Permission Error"), MessageBoxButtons.OK, MessageBoxIcon.Error);
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
                btnToggleUsb.Text = Loc.T("⛔ قفل وتعطيل منافذ USB الآن", "⛔ Block & Disable USB Ports Now");
                btnToggleUsb.BackColor = Color.FromArgb(220, 38, 38);
                btnToggleUsb.ForeColor = Color.White;
            }
            else
            {
                lblUsbStatus.Text = Loc.T("💾 منافذ الفلاشات:  🔴 مقفلة ومحظورة", "💾 Flash Ports:  🔴 Locked & Blocked");
                btnToggleUsb.Text = Loc.T("🔓 فتح وتمكين منافذ USB الآن", "🔓 Unlock & Enable USB Ports Now");
                btnToggleUsb.BackColor = Color.FromArgb(22, 163, 74);
                btnToggleUsb.ForeColor = Color.White;
            }

            // 2. Write-Protect
            bool wpEnabled = IsWriteProtectEnabled();
            if (wpEnabled)
            {
                lblWriteProtectStatus.Text = Loc.T("✍️ الحماية من النسخ:  🛡️ وضع القراءة فقط", "✍️ Copy Protection:  🛡️ Read-Only Mode");
                btnToggleWriteProtect.Text = Loc.T("✍️ السماح بنسخ الملفات (الوضع العادي)", "✍️ Allow File Copy (Normal Mode)");
                btnToggleWriteProtect.BackColor = Color.FromArgb(37, 99, 235);
                btnToggleWriteProtect.ForeColor = Color.White;
            }
            else
            {
                lblWriteProtectStatus.Text = Loc.T("✍️ الحماية من النسخ:  ✍️ النسخ والكتابة مسموحة", "✍️ Copy Protection:  ✍️ Read & Write Allowed");
                btnToggleWriteProtect.Text = Loc.T("🛡️ تفعيل وضع القراءة فقط (حظر النسخ)", "🛡️ Enable Read-Only (Block Writing)");
                btnToggleWriteProtect.BackColor = Color.FromArgb(217, 119, 6);
                btnToggleWriteProtect.ForeColor = Color.White;
            }

            // 3. Auto-Start
            if (lblAutoStartStatus != null && btnToggleAutoStart != null)
            {
                bool autoStart = AutoStartManager.IsAutoStartEnabled();
                if (autoStart)
                {
                    lblAutoStartStatus.Text = Loc.T("🔄 العمل الدائم مع الإقلاع:  🟢 مفعّل باستمرار", "🔄 Persistent Startup:  🟢 Always Enabled");
                    btnToggleAutoStart.Text = Loc.T("🛑 تعطيل التشغيل مع إقلاع الجهاز", "🛑 Disable Startup With Windows");
                    btnToggleAutoStart.BackColor = Color.FromArgb(51, 65, 85);
                    btnToggleAutoStart.ForeColor = Color.White;
                }
                else
                {
                    lblAutoStartStatus.Text = Loc.T("🔄 العمل الدائم مع الإقلاع:  ⚪ متوقف (يدوي)", "🔄 Persistent Startup:  ⚪ Disabled (Manual)");
                    btnToggleAutoStart.Text = Loc.T("⚡ تفعيل العمل التلقائي مع إقلاع ويندوز", "⚡ Enable Auto-Start With Windows");
                    btnToggleAutoStart.BackColor = Color.FromArgb(16, 185, 129);
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
                    bool isWhitelisted = !WhitelistManager.IsWhitelistModeEnabled(); // Allowed by default if whitelist mode disabled

                    if (WhitelistManager.IsWhitelistModeEnabled())
                    {
                        lblLiveIndicator.Text = Loc.T("🔌 [" + time + "] تم فحص الجهاز المتصل بالقائمة البيضاء", "🔌 [" + time + "] USB checked against Whitelist");
                        lblLiveIndicator.ForeColor = Color.FromArgb(251, 191, 36);
                        SecurityLogger.LogEvent("DEVICE_CONNECTED", Loc.T("تم توصيل جهاز USB وفحصه في القائمة البيضاء", "USB Device attached & checked in Whitelist"));
                    }
                    else
                    {
                        lblLiveIndicator.Text = Loc.T("🔌 [" + time + "] تم توصيل جهاز في منفذ USB", "🔌 [" + time + "] USB Device Plugged In");
                        lblLiveIndicator.ForeColor = Color.FromArgb(74, 222, 128);
                        SecurityLogger.LogEvent("DEVICE_CONNECTED", Loc.T("تم توصيل جهاز USB جديد بالجهاز", "USB Device attached"));
                    }

                    string botToken, chatId;
                    AlertNotifier.LoadTelegramConfig(out botToken, out chatId);
                    if (!string.IsNullOrEmpty(botToken) && !string.IsNullOrEmpty(chatId))
                    {
                        string alertText = WhitelistManager.IsWhitelistModeEnabled()
                            ? string.Format("⚠️ [USB Shield - تنبيه القائمة البيضاء] تم توصيل جهاز USB على {0} في تمام {1}. يرجى التحقق من أنه جهاز مصرح به.", Environment.MachineName, time)
                            : string.Format("🔌 [USB Shield] تم توصيل جهاز USB في الجهاز {0} في تمام الساعة: {1}", Environment.MachineName, time);
                        AlertNotifier.SendTelegramAlert(botToken, chatId, alertText);
                    }
                }
                else if (eventType == DBT_DEVICEREMOVECOMPLETE)
                {
                    string time = DateTime.Now.ToString("HH:mm:ss");
                    lblLiveIndicator.Text = Loc.T("⏏️ [" + time + "] تم فصل جهاز من منفذ USB", "⏏️ [" + time + "] USB Device Unplugged");
                    lblLiveIndicator.ForeColor = Color.FromArgb(248, 113, 113);
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
