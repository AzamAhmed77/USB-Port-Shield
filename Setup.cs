using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Forms;
using Microsoft.Win32;

namespace USBPortControllerInstaller
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (!IsAdministrator())
            {
                try
                {
                    ProcessStartInfo proc = new ProcessStartInfo
                    {
                        UseShellExecute = true,
                        WorkingDirectory = Environment.CurrentDirectory,
                        FileName = Application.ExecutablePath,
                        Verb = "runas"
                    };
                    Process.Start(proc);
                }
                catch { }
                return;
            }

            bool isUninstall = (args != null && args.Length > 0 && args[0].ToLower().Contains("uninstall"));
            Application.Run(new InstallerForm(isUninstall));
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

    public class InstallerForm : Form
    {
        private bool isUninstallMode = false;
        private bool isArabic = true;

        private const string AppTitleAr = "درع التحكم في منافذ USB";
        private const string AppTitleEn = "USB Port Controller Shield";
        private const string AppKeyName = "USBPortControllerShield";

        private string installDir;

        // UI Controls
        private Panel mainCard;
        private Label lblTitle;
        private Label lblSubtitle;
        private Label lblStatus;
        private ProgressBar progressBar;
        private Button btnAction;
        private Button btnCancel;
        private Button btnLang;
        private CheckBox chkCreateDesktop;
        private CheckBox chkCreateStartMenu;
        private CheckBox chkLaunchAfter;
        private PictureBox picLogo;
        private Image logoImage;

        public InstallerForm(bool isUninstall)
        {
            this.isUninstallMode = isUninstall;
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            installDir = Path.Combine(programFiles, "USBPortControllerShield");

            LoadLogo();
            InitForm();
            InitUI();
            UpdateLanguage();
        }

        private void LoadLogo()
        {
            try
            {
                string currDir = AppDomain.CurrentDomain.BaseDirectory;
                string logoPath = Path.Combine(currDir, "app_logo.jpg");
                if (File.Exists(logoPath))
                {
                    using (FileStream fs = new FileStream(logoPath, FileMode.Open, FileAccess.Read))
                    {
                        logoImage = Image.FromStream(fs);
                    }
                }

                string icoPath = Path.Combine(currDir, "app.ico");
                if (File.Exists(icoPath))
                {
                    this.Icon = new Icon(icoPath);
                }
            }
            catch { }
        }

        private void InitForm()
        {
            this.Size = new Size(520, 480);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = true;
            this.BackColor = Color.FromArgb(15, 23, 42);
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

        private void InitUI()
        {
            mainCard = new Panel
            {
                Location = new Point(20, 15),
                Size = new Size(465, 410),
                BackColor = Color.FromArgb(30, 41, 59),
                Padding = new Padding(15)
            };
            this.Controls.Add(mainCard);

            // 1. Logo
            picLogo = new PictureBox
            {
                Size = new Size(50, 50),
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = Color.Transparent
            };
            if (logoImage != null) picLogo.Image = logoImage;

            // 2. Language Button
            btnLang = new Button
            {
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
                isArabic = !isArabic;
                UpdateLanguage();
            };

            // 3. Titles
            lblTitle = new Label
            {
                ForeColor = Color.FromArgb(96, 165, 250),
                Font = new Font("Segoe UI", 12.5F, FontStyle.Bold),
                Size = new Size(280, 28)
            };

            lblSubtitle = new Label
            {
                ForeColor = Color.FromArgb(148, 163, 184),
                Font = new Font("Segoe UI", 9F),
                Location = new Point(15, 75),
                Size = new Size(435, 45)
            };

            // 4. Options
            chkCreateDesktop = new CheckBox
            {
                Checked = true,
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(20, 130),
                Size = new Size(425, 25),
                Cursor = Cursors.Hand
            };

            chkCreateStartMenu = new CheckBox
            {
                Checked = true,
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(20, 160),
                Size = new Size(425, 25),
                Cursor = Cursors.Hand
            };

            chkLaunchAfter = new CheckBox
            {
                Checked = true,
                ForeColor = Color.FromArgb(226, 232, 240),
                Location = new Point(20, 190),
                Size = new Size(425, 25),
                Cursor = Cursors.Hand
            };

            // 5. Progress Bar & Status
            lblStatus = new Label
            {
                ForeColor = Color.FromArgb(74, 222, 128),
                Font = new Font("Segoe UI", 9F, FontStyle.Bold),
                Location = new Point(20, 230),
                Size = new Size(425, 22),
                Text = ""
            };

            progressBar = new ProgressBar
            {
                Location = new Point(20, 260),
                Size = new Size(425, 20),
                Style = ProgressBarStyle.Continuous,
                Value = 0,
                Visible = false
            };

            // 6. Action Buttons
            btnAction = new Button
            {
                Location = new Point(20, 305),
                Size = new Size(425, 44),
                BackColor = isUninstallMode ? Color.FromArgb(220, 38, 38) : Color.FromArgb(16, 185, 129),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 10.5F, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            btnAction.FlatAppearance.BorderSize = 0;
            btnAction.Click += BtnAction_Click;

            btnCancel = new Button
            {
                Location = new Point(20, 358),
                Size = new Size(425, 34),
                BackColor = Color.FromArgb(51, 65, 85),
                ForeColor = Color.FromArgb(226, 232, 240),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9F),
                Cursor = Cursors.Hand
            };
            btnCancel.FlatAppearance.BorderSize = 0;
            btnCancel.Click += (s, e) => this.Close();

            mainCard.Controls.Add(picLogo);
            mainCard.Controls.Add(btnLang);
            mainCard.Controls.Add(lblTitle);
            mainCard.Controls.Add(lblSubtitle);

            if (!isUninstallMode)
            {
                mainCard.Controls.Add(chkCreateDesktop);
                mainCard.Controls.Add(chkCreateStartMenu);
                mainCard.Controls.Add(chkLaunchAfter);
            }

            mainCard.Controls.Add(lblStatus);
            mainCard.Controls.Add(progressBar);
            mainCard.Controls.Add(btnAction);
            mainCard.Controls.Add(btnCancel);
        }

        private void UpdateLanguage()
        {
            this.RightToLeft = isArabic ? RightToLeft.Yes : RightToLeft.No;
            btnLang.Text = isArabic ? "🌐 English" : "🌐 العربية";

            if (isArabic)
            {
                picLogo.Location = new Point(400, 10);
                btnLang.Location = new Point(15, 12);
                lblTitle.Location = new Point(115, 15);
                lblTitle.TextAlign = ContentAlignment.MiddleRight;
                lblSubtitle.TextAlign = ContentAlignment.TopRight;
                lblStatus.TextAlign = ContentAlignment.MiddleRight;

                this.Text = isUninstallMode ? "معالج إلغاء تثبيت درع منافذ USB" : "معالج تنصيب درع منافذ USB";
                lblTitle.Text = isUninstallMode ? "إلغاء تثبيت التطبيق" : "تنصيب درع منافذ USB";
                lblSubtitle.Text = isUninstallMode
                    ? "سيتم إزالة برنامج درع منافذ USB والاختصارات بالكامل من جهازك."
                    : "مرحباً بك في معالج تثبيت التطبيق الأمني الرسمي لحماية منافذ USB على نظام التشغيل ويندوز.";

                chkCreateDesktop.Text = "إنشاء اختصار على سطح المكتب";
                chkCreateStartMenu.Text = "إضافة إلى قائمة ابدأ (Start Menu)";
                chkLaunchAfter.Text = "تشغيل البرنامج فور انتهاء التثبيت";

                btnAction.Text = isUninstallMode ? "حذف وإلغاء التثبيت الآن 🗑️" : "بدء التنصيب والتثبيت الآن 🚀";
                btnCancel.Text = "إلغاء / خروج";
            }
            else
            {
                picLogo.Location = new Point(15, 10);
                btnLang.Location = new Point(355, 12);
                lblTitle.Location = new Point(75, 15);
                lblTitle.TextAlign = ContentAlignment.MiddleLeft;
                lblSubtitle.TextAlign = ContentAlignment.TopLeft;
                lblStatus.TextAlign = ContentAlignment.MiddleLeft;

                this.Text = isUninstallMode ? "USB Port Shield Uninstaller" : "USB Port Shield Setup Wizard";
                lblTitle.Text = isUninstallMode ? "Uninstall Application" : "USB Port Shield Setup";
                lblSubtitle.Text = isUninstallMode
                    ? "This will completely remove USB Port Controller Shield and all its shortcuts from your computer."
                    : "Welcome to the official setup wizard for USB Port Controller Shield security system on Windows.";

                chkCreateDesktop.Text = "Create Desktop Shortcut";
                chkCreateStartMenu.Text = "Add to Start Menu Programs";
                chkLaunchAfter.Text = "Launch application after installation";

                btnAction.Text = isUninstallMode ? "Uninstall Now 🗑️" : "Install Now 🚀";
                btnCancel.Text = "Cancel / Exit";
            }
        }

        private void BtnAction_Click(object sender, EventArgs e)
        {
            btnAction.Enabled = false;
            btnCancel.Enabled = false;
            progressBar.Visible = true;

            if (isUninstallMode)
            {
                PerformUninstall();
            }
            else
            {
                PerformInstall();
            }
        }

        private void PerformInstall()
        {
            try
            {
                lblStatus.Text = isArabic ? "جاري تجهيز مسار التثبيت..." : "Preparing installation directory...";
                progressBar.Value = 20;
                Application.DoEvents();

                // 1. Create install directory
                if (!Directory.Exists(installDir))
                {
                    Directory.CreateDirectory(installDir);
                }

                // 2. Kill existing running processes if any
                KillRunningApp();

                // 3. Copy files
                lblStatus.Text = isArabic ? "جاري نسخ ملفات البرنامج..." : "Copying application files...";
                progressBar.Value = 45;
                Application.DoEvents();

                string currentDir = AppDomain.CurrentDomain.BaseDirectory;
                string exePath = Path.Combine(installDir, "USBController.exe");
                string logoPath = Path.Combine(installDir, "app_logo.jpg");
                string icoPath = Path.Combine(installDir, "app.ico");
                string uninstallerPath = Path.Combine(installDir, "Uninstall.exe");

                if (File.Exists(Path.Combine(currentDir, "USBController.exe")))
                    File.Copy(Path.Combine(currentDir, "USBController.exe"), exePath, true);

                if (File.Exists(Path.Combine(currentDir, "app_logo.jpg")))
                    File.Copy(Path.Combine(currentDir, "app_logo.jpg"), logoPath, true);

                if (File.Exists(Path.Combine(currentDir, "app.ico")))
                    File.Copy(Path.Combine(currentDir, "app.ico"), icoPath, true);

                // Copy installer itself as uninstaller
                File.Copy(Application.ExecutablePath, uninstallerPath, true);

                // 4. Create Shortcuts
                lblStatus.Text = isArabic ? "جاري إنشاء الاختصارات..." : "Creating shortcuts...";
                progressBar.Value = 70;
                Application.DoEvents();

                string shortcutTitle = isArabic ? AppTitleAr : AppTitleEn;

                if (chkCreateDesktop.Checked)
                {
                    string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
                    CreateShortcut(Path.Combine(desktopPath, shortcutTitle + ".lnk"), exePath, icoPath, "USB Port Controller Shield");
                }

                if (chkCreateStartMenu.Checked)
                {
                    string startMenu = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
                    string appFolder = Path.Combine(startMenu, "USB Port Controller Shield");
                    if (!Directory.Exists(appFolder)) Directory.CreateDirectory(appFolder);

                    CreateShortcut(Path.Combine(appFolder, shortcutTitle + ".lnk"), exePath, icoPath, "USB Port Controller Shield");
                    CreateShortcut(Path.Combine(appFolder, (isArabic ? "إلغاء التثبيت" : "Uninstall") + ".lnk"), uninstallerPath, icoPath, "Uninstall USB Port Controller Shield", "-uninstall");
                }

                // 5. Register in Windows Programs & Features (Add/Remove Programs)
                lblStatus.Text = isArabic ? "تسجيل البرنامج في لوحة التحكم..." : "Registering in Windows Control Panel...";
                progressBar.Value = 85;
                Application.DoEvents();

                RegisterInAddRemovePrograms(installDir, exePath, uninstallerPath, icoPath);

                progressBar.Value = 100;
                lblStatus.Text = isArabic ? "✔ تم التثبيت بنجاح تام!" : "✔ Installation completed successfully!";

                MessageBox.Show(
                    isArabic ? "تم تنصيب برنامج درع منافذ USB بنجاح على جهازك!" : "USB Port Controller Shield has been successfully installed!",
                    isArabic ? "اكتمال التثبيت" : "Installation Complete",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );

                if (chkLaunchAfter.Checked && File.Exists(exePath))
                {
                    Process.Start(new ProcessStartInfo
                    {
                        FileName = exePath,
                        UseShellExecute = true,
                        WorkingDirectory = installDir
                    });
                }

                this.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show((isArabic ? "حدث خطأ أثناء التثبيت:\n" : "Error during installation:\n") + ex.Message, isArabic ? "خطأ" : "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                btnAction.Enabled = true;
                btnCancel.Enabled = true;
            }
        }

        private void PerformUninstall()
        {
            try
            {
                lblStatus.Text = isArabic ? "جاري إيقاف البرنامج وإزالة الملفات..." : "Stopping service and removing files...";
                progressBar.Value = 30;
                Application.DoEvents();

                KillRunningApp();

                // 1. Remove Shortcuts
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
                SafeDeleteFile(Path.Combine(desktopPath, AppTitleAr + ".lnk"));
                SafeDeleteFile(Path.Combine(desktopPath, AppTitleEn + ".lnk"));

                string startMenu = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
                string appFolder = Path.Combine(startMenu, "USB Port Controller Shield");
                if (Directory.Exists(appFolder))
                {
                    try { Directory.Delete(appFolder, true); } catch { }
                }

                // 2. Remove Registry Entry
                progressBar.Value = 60;
                UnregisterFromAddRemovePrograms();

                // 3. Remove Run Key
                try
                {
                    using (RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    {
                        if (key != null) key.DeleteValue(AppKeyName, false);
                    }
                }
                catch { }

                // 4. Schedule directory removal via self-deleting cmd
                progressBar.Value = 100;
                lblStatus.Text = isArabic ? "✔ تم إلغاء التثبيت بنجاح!" : "✔ Uninstalled successfully!";

                MessageBox.Show(
                    isArabic ? "تم إلغاء تثبيت برنامج درع منافذ USB بنجاح." : "USB Port Controller Shield has been uninstalled successfully.",
                    isArabic ? "تم الإلغاء" : "Uninstall Complete",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );

                // Self delete directory after exit
                string cmd = string.Format("/c ping 127.0.0.1 -n 2 > nul & rmdir /s /q \"{0}\"", installDir);
                Process.Start(new ProcessStartInfo
                {
                    FileName = "cmd.exe",
                    Arguments = cmd,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });

                this.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show((isArabic ? "حدث خطأ أثناء إلغاء التثبيت:\n" : "Error during uninstall:\n") + ex.Message, isArabic ? "خطأ" : "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                btnAction.Enabled = true;
                btnCancel.Enabled = true;
            }
        }

        private void KillRunningApp()
        {
            try
            {
                foreach (Process p in Process.GetProcessesByName("USBController"))
                {
                    try { p.Kill(); p.WaitForExit(1000); } catch { }
                }
            }
            catch { }
        }

        private void SafeDeleteFile(string path)
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
            }
            catch { }
        }

        private void RegisterInAddRemovePrograms(string installPath, string exePath, string uninstallerPath, string icoPath)
        {
            try
            {
                string regKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\" + AppKeyName;
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(regKeyPath))
                {
                    if (key != null)
                    {
                        key.SetValue("DisplayName", AppTitleAr + " (" + AppTitleEn + ")", RegistryValueKind.String);
                        key.SetValue("DisplayIcon", icoPath, RegistryValueKind.String);
                        key.SetValue("DisplayVersion", "1.0.0", RegistryValueKind.String);
                        key.SetValue("Publisher", "Security & System Admin", RegistryValueKind.String);
                        key.SetValue("InstallLocation", installPath, RegistryValueKind.String);
                        key.SetValue("UninstallString", "\"" + uninstallerPath + "\" -uninstall", RegistryValueKind.String);
                        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
                        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                    }
                }
            }
            catch { }
        }

        private void UnregisterFromAddRemovePrograms()
        {
            try
            {
                string regKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(regKeyPath, true))
                {
                    if (key != null)
                    {
                        key.DeleteSubKeyTree(AppKeyName, false);
                    }
                }
            }
            catch { }
        }

        private void CreateShortcut(string shortcutPath, string targetPath, string iconPath, string description, string arguments = "")
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType != null)
                {
                    dynamic shell = Activator.CreateInstance(shellType);
                    dynamic shortcut = shell.CreateShortcut(shortcutPath);
                    shortcut.TargetPath = targetPath;
                    shortcut.WorkingDirectory = Path.GetDirectoryName(targetPath);
                    shortcut.Description = description;
                    if (!string.IsNullOrEmpty(arguments)) shortcut.Arguments = arguments;
                    if (!string.IsNullOrEmpty(iconPath) && File.Exists(iconPath)) shortcut.IconLocation = iconPath + ",0";
                    shortcut.Save();
                }
            }
            catch { }
        }
    }
}
