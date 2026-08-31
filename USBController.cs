using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
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
                            return storedHash == calculatedHash;
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
            ChangePassword
        }

        private CurrentViewType activeView = CurrentViewType.Unlock;

        private Panel contentCard;
        private Image logoImage;

        // عناصر واجهة التحكم
        private Label lblUsbStatus;
        private Button btnToggleUsb;
        private Label lblWriteProtectStatus;
        private Button btnToggleWriteProtect;
        private Label lblAutoStartStatus;
        private Button btnToggleAutoStart;
        private Label lblLiveIndicator;
        private NotifyIcon trayIcon;

        public UnifiedMainForm(bool startInBackground = false)
        {
            LoadEmbeddedLogo();
            ApplyFormStyling();

            InitCardContainer();
            InitTrayIcon();

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
            this.Text = Loc.T("درع التحكم في منافذ USB", "USB Port Controller Shield");
            this.Size = new Size(480, 440);
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
                Location = new Point(18, 15),
                Size = new Size(428, 370),
                BackColor = Color.FromArgb(30, 41, 59),
                Padding = new Padding(15)
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
                Size = new Size(95, 26),
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
            if (logoImage != null)
            {
                pic.Image = logoImage;
            }
            return pic;
        }

        #region View 1: شاشة إدخال كلمة السر لفتح القفل
        private void ShowUnlockView()
        {
            activeView = CurrentViewType.Unlock;
            contentCard.Controls.Clear();

            // زر اللغة
            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(15, 12) : new Point(318, 12);

            // صورة الشعار
            PictureBox picLogo = CreateLogoHeader(48);
            picLogo.Location = Loc.IsArabic ? new Point(365, 10) : new Point(15, 10);

            Label lblTitle = new Label
            {
                Text = Loc.T("🔐 التطبيق محمي بكلمة سر", "🔐 Application is Locked"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 12F, FontStyle.Bold),
                Location = Loc.IsArabic ? new Point(115, 15) : new Point(70, 15),
                Size = new Size(245, 28),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblDesc = new Label
            {
                Text = Loc.T("أدخل كلمة السر الرئيسية للوصول للتحكم بمنافذ USB:", "Enter master password to access USB port controls:"),
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 9F),
                Location = new Point(15, 70),
                Size = new Size(398, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            TextBox txtPassword = new TextBox
            {
                Location = new Point(15, 100),
                Size = new Size(398, 30),
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
                Location = new Point(15, 145),
                Size = new Size(398, 22),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Button btnUnlock = new Button
            {
                Text = Loc.T("فتح القفل 🔓", "Unlock 🔓"),
                Location = new Point(15, 185),
                Size = new Size(398, 45),
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
                Location = new Point(15, 245),
                Size = new Size(398, 38),
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

        #region View 2: شاشة إعداد كلمة السر لأول مرة
        private void ShowSetupPasswordView()
        {
            activeView = CurrentViewType.SetupPassword;
            contentCard.Controls.Clear();

            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(15, 10) : new Point(318, 10);

            PictureBox picLogo = CreateLogoHeader(42);
            picLogo.Location = Loc.IsArabic ? new Point(370, 8) : new Point(15, 8);

            Label lblTitle = new Label
            {
                Text = Loc.T("🔒 تعيين كلمة سر رئيسية", "🔒 Set Master Password"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 11.5F, FontStyle.Bold),
                Location = Loc.IsArabic ? new Point(115, 12) : new Point(65, 12),
                Size = new Size(250, 26),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblPass = new Label
            {
                Text = Loc.T("كلمة السر الجديدة:", "New Password:"),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(15, 55),
                Size = new Size(398, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };
            TextBox txtNew = new TextBox { Location = new Point(15, 80), Size = new Size(398, 26), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Label lblConf = new Label
            {
                Text = Loc.T("تأكيد كلمة السر:", "Confirm Password:"),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(15, 120),
                Size = new Size(398, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };
            TextBox txtConf = new TextBox { Location = new Point(15, 145), Size = new Size(398, 26), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Label lblErr = new Label
            {
                Text = "",
                ForeColor = Color.FromArgb(248, 113, 113),
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Location = new Point(15, 180),
                Size = new Size(398, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Button btnSave = new Button
            {
                Text = Loc.T("حفظ ومتابعة ✔", "Save & Continue ✔"),
                Location = new Point(15, 210),
                Size = new Size(398, 42),
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

        #region View 3: شاشة التحكم في المنافذ والخدمة المستمرة
        private void ShowControlView()
        {
            activeView = CurrentViewType.Control;
            contentCard.Controls.Clear();

            // صورة الشعار
            PictureBox picLogo = CreateLogoHeader(34);
            picLogo.Location = Loc.IsArabic ? new Point(380, 8) : new Point(15, 8);

            Label lblTitle = new Label
            {
                Text = Loc.T("🛡️ درع منافذ USB", "🛡️ USB Shield"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 11F, FontStyle.Bold),
                Location = Loc.IsArabic ? new Point(230, 10) : new Point(55, 10),
                Size = new Size(145, 26),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Button btnLang = CreateLangSwitchButton();
            btnLang.Size = new Size(80, 26);
            btnLang.Location = Loc.IsArabic ? new Point(145, 8) : new Point(205, 8);

            Button btnChangePass = new Button
            {
                Text = Loc.T("🔑 رمز", "🔑 Pass"),
                Size = new Size(60, 26),
                Location = Loc.IsArabic ? new Point(80, 8) : new Point(290, 8),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnChangePass.FlatAppearance.BorderSize = 0;
            btnChangePass.Click += (s, e) => ShowChangePasswordView();

            Button btnLock = new Button
            {
                Text = Loc.T("🔒 قفل", "🔒 Lock"),
                Size = new Size(60, 26),
                Location = Loc.IsArabic ? new Point(15, 8) : new Point(355, 8),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 8.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnLock.FlatAppearance.BorderSize = 0;
            btnLock.Click += (s, e) => ShowUnlockView();

            // 2. قسم منافذ فلاشات USB
            lblUsbStatus = new Label
            {
                Text = Loc.T("💾 منافذ الفلاشات: جاري الفحص...", "💾 USB Storage: Checking..."),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(15, 42),
                Size = new Size(398, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            btnToggleUsb = new Button
            {
                Text = Loc.T("تغيير الحالة", "Toggle Status"),
                Location = new Point(15, 65),
                Size = new Size(398, 38),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnToggleUsb.FlatAppearance.BorderSize = 0;
            btnToggleUsb.Click += BtnToggleUsb_Click;

            // 3. قسم وضع الحماية من النسخ (Write-Protect)
            lblWriteProtectStatus = new Label
            {
                Text = Loc.T("✍️ الحماية من النسخ: جاري الفحص...", "✍️ Write Protection: Checking..."),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(15, 110),
                Size = new Size(398, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            btnToggleWriteProtect = new Button
            {
                Text = Loc.T("تغيير وضع الحماية", "Toggle Protection"),
                Location = new Point(15, 133),
                Size = new Size(398, 38),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnToggleWriteProtect.FlatAppearance.BorderSize = 0;
            btnToggleWriteProtect.Click += BtnToggleWriteProtect_Click;

            // 4. قسم التشغيل التلقائي مع إقلاع الجهاز
            lblAutoStartStatus = new Label
            {
                Text = Loc.T("🔄 الحماية مع إقلاع الويندوز: جاري الفحص...", "🔄 Startup Protection: Checking..."),
                ForeColor = Color.FromArgb(226, 232, 240),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(15, 178),
                Size = new Size(398, 20),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            btnToggleAutoStart = new Button
            {
                Text = Loc.T("تبديل وضع الإقلاع", "Toggle Startup Mode"),
                Location = new Point(15, 201),
                Size = new Size(398, 38),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnToggleAutoStart.FlatAppearance.BorderSize = 0;
            btnToggleAutoStart.Click += BtnToggleAutoStart_Click;

            // 5. زر إيقاف الخدمة والخروج تماماً
            Button btnStopService = new Button
            {
                Text = Loc.T("🛑 إيقاف الحماية والخروج تماماً", "🛑 Stop Protection & Exit Completely"),
                Location = new Point(15, 250),
                Size = new Size(398, 38),
                BackColor = Color.FromArgb(185, 28, 28),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnStopService.FlatAppearance.BorderSize = 0;
            btnStopService.Click += (s, e) => ExitApplication();

            // 6. مؤشر المراقبة الحية
            lblLiveIndicator = new Label
            {
                Text = Loc.T("🟢 الحماية نشطة ومستمرة (يكتشف الأجهزة تلقائياً)", "🟢 Protection Active & Persistent (Auto-detects Devices)"),
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 8.5F),
                Location = new Point(15, 298),
                Size = new Size(398, 20),
                TextAlign = ContentAlignment.MiddleCenter
            };

            contentCard.Controls.Add(picLogo);
            contentCard.Controls.Add(lblTitle);
            contentCard.Controls.Add(btnLang);
            contentCard.Controls.Add(btnChangePass);
            contentCard.Controls.Add(btnLock);
            contentCard.Controls.Add(lblUsbStatus);
            contentCard.Controls.Add(btnToggleUsb);
            contentCard.Controls.Add(lblWriteProtectStatus);
            contentCard.Controls.Add(btnToggleWriteProtect);
            contentCard.Controls.Add(lblAutoStartStatus);
            contentCard.Controls.Add(btnToggleAutoStart);
            contentCard.Controls.Add(btnStopService);
            contentCard.Controls.Add(lblLiveIndicator);

            RefreshAllStatus();
        }
        #endregion

        #region View 4: شاشة تغيير كلمة السر
        private void ShowChangePasswordView()
        {
            activeView = CurrentViewType.ChangePassword;
            contentCard.Controls.Clear();

            Button btnLang = CreateLangSwitchButton();
            btnLang.Location = Loc.IsArabic ? new Point(15, 10) : new Point(318, 10);

            PictureBox picLogo = CreateLogoHeader(38);
            picLogo.Location = Loc.IsArabic ? new Point(375, 8) : new Point(15, 8);

            Label lblTitle = new Label
            {
                Text = Loc.T("🔑 تغيير كلمة السر", "🔑 Change Password"),
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 11.5F, FontStyle.Bold),
                Location = Loc.IsArabic ? new Point(120, 12) : new Point(60, 12),
                Size = new Size(245, 24),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };

            Label lblCur = new Label
            {
                Text = Loc.T("كلمة السر الحالية:", "Current Password:"),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(15, 48),
                Size = new Size(398, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };
            TextBox txtCurrent = new TextBox { Location = new Point(15, 70), Size = new Size(398, 24), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Label lblNew = new Label
            {
                Text = Loc.T("كلمة السر الجديدة:", "New Password:"),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(15, 105),
                Size = new Size(398, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };
            TextBox txtNew = new TextBox { Location = new Point(15, 128), Size = new Size(398, 24), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Label lblConf = new Label
            {
                Text = Loc.T("تأكيد كلمة السر الجديدة:", "Confirm New Password:"),
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(15, 162),
                Size = new Size(398, 18),
                TextAlign = Loc.IsArabic ? ContentAlignment.MiddleRight : ContentAlignment.MiddleLeft
            };
            TextBox txtConf = new TextBox { Location = new Point(15, 185), Size = new Size(398, 24), PasswordChar = '●', BackColor = Color.FromArgb(15, 23, 42), ForeColor = Color.White, BorderStyle = BorderStyle.FixedSingle };

            Button btnSave = new Button
            {
                Text = Loc.T("حفظ التغيير", "Save Change"),
                Location = Loc.IsArabic ? new Point(15, 230) : new Point(15, 230),
                Size = new Size(210, 38),
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
                Location = Loc.IsArabic ? new Point(235, 230) : new Point(235, 230),
                Size = new Size(178, 38),
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
                    MessageBox.Show(
                        Loc.T("كلمة السر الحالية غير صحيحة!", "Current password is incorrect!"),
                        Loc.T("خطأ", "Error"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return;
                }
                if (string.IsNullOrEmpty(txtNew.Text))
                {
                    MessageBox.Show(
                        Loc.T("يرجى إدخال كلمة السر الجديدة!", "Please enter the new password!"),
                        Loc.T("تنبيه", "Warning"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning
                    );
                    return;
                }
                if (txtNew.Text != txtConf.Text)
                {
                    MessageBox.Show(
                        Loc.T("كلمتا السر غير متطابقتين!", "Passwords do not match!"),
                        Loc.T("خطأ", "Error"),
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return;
                }

                if (PasswordManager.SetPassword(txtNew.Text))
                {
                    MessageBox.Show(
                        Loc.T("تم تحديث كلمة السر بنجاح!", "Password updated successfully!"),
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
                    }
                    else
                    {
                        MessageBox.Show(
                            Loc.T("تعذر الوصول إلى مسار سجل USBSTOR!", "Cannot access USBSTOR registry path!"),
                            Loc.T("خطأ", "Error"),
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Error
                        );
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    Loc.T("حدث خطأ أثناء تعديل السجل:\n", "Error modifying registry:\n") + ex.Message,
                    Loc.T("خطأ في الصلاحيات", "Permission Error"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
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
                            return wpVal == 1; // 1 = Write Protected (Read-only), 0 = Normal
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
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    Loc.T("حدث خطأ أثناء تعديل وضع الحماية من الكتابة:\n", "Error modifying write protection:\n") + ex.Message,
                    Loc.T("خطأ", "Error"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
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
            RefreshAllStatus();
        }
        #endregion

        private void RefreshAllStatus()
        {
            if (lblUsbStatus == null || btnToggleUsb == null) return;

            // 1. تحديث حالة USB
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

            // 2. تحديث حالة Write Protect
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

            // 3. تحديث حالة التشغيل التلقائي
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
                    lblLiveIndicator.Text = Loc.T(
                        "🔌 [" + DateTime.Now.ToString("HH:mm:ss") + "] تم توصيل جهاز في منفذ USB",
                        "🔌 [" + DateTime.Now.ToString("HH:mm:ss") + "] USB Device Plugged In"
                    );
                    lblLiveIndicator.ForeColor = Color.FromArgb(74, 222, 128);
                }
                else if (eventType == DBT_DEVICEREMOVECOMPLETE)
                {
                    lblLiveIndicator.Text = Loc.T(
                        "⏏️ [" + DateTime.Now.ToString("HH:mm:ss") + "] تم فصل جهاز من منفذ USB",
                        "⏏️ [" + DateTime.Now.ToString("HH:mm:ss") + "] USB Device Unplugged"
                    );
                    lblLiveIndicator.ForeColor = Color.FromArgb(248, 113, 113);
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
