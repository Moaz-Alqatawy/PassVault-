using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using PassVault.Dialogs;
using PassVault.Models;
using PassVault.Security;
using PassVault.Storage;

namespace PassVault;

public partial class MainWindow : Window
{
    private readonly VaultCrypto _crypto = new();
    private readonly VaultStore _store;
    private readonly DispatcherTimer _idleTimer;
    private readonly DispatcherTimer _clipboardTimer;
    private readonly ObservableCollection<ApplicationEntry> _applications = [];
    private VaultSession? _session;
    private Guid? _selectedApplicationId;
    private DateTime _lastActivity = DateTime.UtcNow;
    private string? _clipboardSecret;
    private bool _showPasswords;
    private bool _refreshing;
    private bool _includePasswordsInPdf;
    private bool _closing;

    public MainWindow()
    {
        InitializeComponent();
        _store = new VaultStore(_crypto);
        ApplicationsList.ItemsSource = _applications;
        InputManager.Current.PreProcessInput += InputManager_PreProcessInput;
        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _idleTimer.Tick += IdleTimer_Tick;
        _clipboardTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _clipboardTimer.Tick += ClipboardTimer_Tick;
        Loaded += MainWindow_Loaded;
        Closing += MainWindow_Closing;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_store.Exists)
            {
                if (!UnlockLoop()) { _closing = true; Close(); return; }
            }
            else
            {
                _session = _store.Create("0979");
                MessageBox.Show(this,
                    "تم إنشاء خزنتك بكلمة المرور الابتدائية 0979.\nهذه كلمة مرور ضعيفة ومعروفة؛ غيّرها الآن من الإعدادات قبل حفظ بيانات حقيقية.\n\nإذا نسيت كلمة المرور الرئيسية فلن يمكن استعادة البيانات المشفّرة.",
                    "تنبيه أمني مهم", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            RepairIdleSettingsIfNeeded();
            RefreshApplications();
            _lastActivity = DateTime.UtcNow;
            _idleTimer.Start();
            if (_session is not null && _session.Data.Applications.Count == 0)
                StatusText.Text = $"أضف تطبيقًا للبدء · ملف الخزنة: {_store.VaultPath}";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or InvalidDataException)
        {
            MessageBox.Show(this, "تعذّر فتح الخزنة أو إنشاء ملفها. تحقق من صلاحيات مجلد بيانات المستخدم أو استعد نسخة احتياطية.\n\n" + ex.Message,
                "تعذّر بدء PassVault", MessageBoxButton.OK, MessageBoxImage.Error);
            _closing = true;
            Close();
        }
    }

    private bool UnlockLoop()
    {
        while (true)
        {
            var password = DialogFactory.PromptPassword(this, "فتح PassVault", "أدخل كلمة المرور الرئيسية لفتح خزنتك.");
            if (password is null) return false;
            try
            {
                _session = _store.Unlock(password);
                _lastActivity = DateTime.UtcNow;
                return true;
            }
            catch (CryptographicException)
            {
                MessageBox.Show(this, "كلمة المرور غير صحيحة. لم يتم تغيير أي بيانات.", "تعذّر فتح الخزنة",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            catch (InvalidDataException)
            {
                MessageBox.Show(this, "ملف الخزنة تالف أو بتنسيق غير معروف. حاول استعادة نسخة احتياطية.", "ملف غير صالح",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
            catch (IOException ex)
            {
                MessageBox.Show(this, "تعذّر قراءة ملف الخزنة.\n" + ex.Message, "خطأ في القراءة",
                    MessageBoxButton.OK, MessageBoxImage.Error);
                return false;
            }
        }
    }

    private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        _idleTimer.Stop();
        _clipboardTimer.Stop();
        _session?.Dispose();
        _session = null;
        InputManager.Current.PreProcessInput -= InputManager_PreProcessInput;
    }

    private void Window_PreviewKeyDown(object sender, KeyEventArgs e) => MarkActivity();
    private void Window_PreviewMouseDown(object sender, MouseButtonEventArgs e) => MarkActivity();
    private void Window_PreviewMouseMove(object sender, MouseEventArgs e) => MarkActivity();
    private void InputManager_PreProcessInput(object sender, PreProcessInputEventArgs e)
    {
        if (e.StagingItem.Input is KeyEventArgs or MouseEventArgs) MarkActivity();
    }

    private void MarkActivity()
    {
        _lastActivity = DateTime.UtcNow;
    }

    private void IdleTimer_Tick(object? sender, EventArgs e)
    {
        if (_session is null || _closing) return;
        if (DateTime.UtcNow - _lastActivity >= TimeSpan.FromMinutes(ReadIdleMinutes()))
            LockVault();
    }

    private void RepairIdleSettingsIfNeeded()
    {
        _ = ReadIdleMinutes();
    }

    private int ReadIdleMinutes()
    {
        try { return _store.ReadIdleMinutes(); }
        catch (InvalidDataException)
        {
            MessageBox.Show(this, "ملف إعداد مدة القفل التلقائي تالف. ستُستخدم مدة 5 دقائق؛ لم تتأثر بيانات الخزنة.",
                "إعداد غير صالح", MessageBoxButton.OK, MessageBoxImage.Warning);
            try { _store.SaveIdleMinutes(5); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                MessageBox.Show(this, "تعذّر إصلاح ملف الإعدادات؛ سيُستخدم القفل بعد 5 دقائق لهذه الجلسة.\n" + ex.Message,
                    "تعذّر حفظ الإعداد", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return 5;
        }
    }

    private void Lock_Click(object sender, RoutedEventArgs e) => LockVault();

    private void LockVault()
    {
        if (_session is null) return;
        _session.Dispose();
        _session = null;
        ClearOwnedClipboard();
        _applications.Clear();
        AccountsGrid.ItemsSource = null;
        _selectedApplicationId = null;
        SelectedApplicationName.Text = "الخزنة مقفلة";
        AccountsSummary.Text = "أدخل كلمة المرور الرئيسية للمتابعة";
        EmptyState.Visibility = Visibility.Collapsed;
        StatusText.Text = "تم قفل الخزنة";
        if (!UnlockLoop())
        {
            _closing = true;
            Close();
            return;
        }
        RefreshApplications();
        _idleTimer.Start();
        MarkActivity();
    }

    private void RefreshApplications()
    {
        if (_session is null) return;
        _refreshing = true;
        var oldSelection = _selectedApplicationId;
        _applications.Clear();
        foreach (var app in _session.Data.Applications.OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase))
            _applications.Add(app);
        var selected = _applications.FirstOrDefault(a => a.Id == oldSelection);
        ApplicationsList.SelectedItem = selected;
        if (selected is null) _selectedApplicationId = null;
        _refreshing = false;
        RefreshAccounts();
    }

    private void ApplicationsList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_refreshing) return;
        _selectedApplicationId = (ApplicationsList.SelectedItem as ApplicationEntry)?.Id;
        RefreshAccounts();
    }

    private void RefreshAccounts()
    {
        if (_session is null) return;
        var app = _session.Data.Applications.FirstOrDefault(a => a.Id == _selectedApplicationId);
        SelectedApplicationName.Text = app?.Name ?? "كل الحسابات";
        var query = SearchBox.Text?.Trim() ?? "";
        var accounts = _session.Data.Accounts
            .Where(a => _selectedApplicationId is null || a.ApplicationId == _selectedApplicationId)
            .Where(a => query.Length == 0 || Matches(a, query))
            .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
            .Select(a => new AccountRow { Account = a, PasswordDisplay = _showPasswords ? a.Password : "••••••••" })
            .ToList();
        AccountsGrid.ItemsSource = accounts;
        AccountsSummary.Text = accounts.Count == 1 ? "حساب واحد" : $"{accounts.Count} حسابات";
        EmptyState.Visibility = accounts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private static bool Matches(AccountEntry account, string query) =>
        account.Name.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
        account.Username.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
        account.Phone.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
        account.Email.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
        account.Notes.Contains(query, StringComparison.CurrentCultureIgnoreCase);

    private AccountEntry? SelectedAccount => (AccountsGrid.SelectedItem as AccountRow)?.Account;

    private void SearchBox_TextChanged(object sender, TextChangedEventArgs e) => RefreshAccounts();

    private void AddApplication_Click(object sender, RoutedEventArgs e)
    {
        var app = DialogFactory.AddApplication(this);
        if (app is null) return;
        if (_session!.Data.Applications.Any(a => a.Name.Equals(app.Name, StringComparison.CurrentCultureIgnoreCase)))
        {
            MessageBox.Show(this, "يوجد تطبيق بهذا الاسم بالفعل.", "اسم مكرر", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (TryChange(() => _session.Data.Applications.Add(app)))
        {
            _selectedApplicationId = app.Id;
            RefreshApplications();
            ApplicationsList.SelectedItem = _applications.FirstOrDefault(a => a.Id == app.Id);
            StatusText.Text = "تمت إضافة التطبيق.";
        }
    }

    private void DeleteApplication_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null || _selectedApplicationId is null)
        {
            MessageBox.Show(this, "اختر تطبيقًا من القائمة أولًا.", "لا يوجد تطبيق محدد", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var app = _session.Data.Applications.First(a => a.Id == _selectedApplicationId);
        var count = _session.Data.Accounts.Count(a => a.ApplicationId == app.Id);
        if (MessageBox.Show(this, $"سيحذف التطبيق «{app.Name}» وجميع حساباته ({count}). هل تريد المتابعة؟",
                "تأكيد حذف التطبيق", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        if (TryChange(() =>
            {
                _session.Data.Applications.RemoveAll(a => a.Id == app.Id);
                _session.Data.Accounts.RemoveAll(a => a.ApplicationId == app.Id);
            }))
        {
            _selectedApplicationId = null;
            RefreshApplications();
            StatusText.Text = "تم حذف التطبيق وحساباته.";
        }
    }

    private void AddAccount_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        if (_session.Data.Applications.Count == 0)
        {
            MessageBox.Show(this, "أضف تطبيقًا أولًا، ثم أضف الحسابات التابعة له.", "أضف تطبيقًا",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var appId = _selectedApplicationId ?? ChooseApplication();
        if (appId is null) return;
        var account = DialogFactory.EditAccount(this, null, appId.Value);
        if (account is null) return;
        if (TryChange(() => _session.Data.Accounts.Add(account)))
        {
            _selectedApplicationId = appId;
            RefreshApplications();
            StatusText.Text = "تم حفظ الحساب مشفّرًا.";
        }
    }

    private Guid? ChooseApplication()
    {
        var window = new Window
        {
            Owner = this, Title = "اختر تطبيقًا", Width = 380, Height = 410, ResizeMode = ResizeMode.CanResize,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = new SolidColorBrush(Color.FromRgb(245, 247, 250)),
            FlowDirection = FlowDirection.RightToLeft
        };
        var list = new ListBox { ItemsSource = _session!.Data.Applications, DisplayMemberPath = "Name", Margin = new Thickness(18) };
        var panel = new DockPanel();
        var confirm = new Button { Content = "اختيار", Margin = new Thickness(18), HorizontalAlignment = HorizontalAlignment.Left };
        DockPanel.SetDock(confirm, Dock.Bottom);
        panel.Children.Add(confirm);
        panel.Children.Add(list);
        Guid? result = null;
        confirm.Click += (_, _) =>
        {
            if (list.SelectedItem is ApplicationEntry chosen)
            {
                result = chosen.Id;
                window.DialogResult = true;
            }
        };
        window.Content = panel;
        return window.ShowDialog() == true ? result : null;
    }

    private void EditAccount_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedAccount is not { } current)
        {
            MessageBox.Show(this, "اختر حسابًا لتعديله.", "لا يوجد حساب محدد", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var updated = DialogFactory.EditAccount(this, current, current.ApplicationId);
        if (updated is null) return;
        if (TryChange(() =>
            {
                var index = _session!.Data.Accounts.FindIndex(a => a.Id == current.Id);
                _session.Data.Accounts[index] = updated;
            }))
        {
            RefreshAccounts();
            StatusText.Text = "تم تحديث الحساب.";
        }
    }

    private void DeleteAccount_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedAccount is not { } account)
        {
            MessageBox.Show(this, "اختر حسابًا لحذفه.", "لا يوجد حساب محدد", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show(this, $"هل تريد حذف الحساب «{account.Name}» نهائيًا؟", "تأكيد الحذف",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        if (TryChange(() => { _session!.Data.Accounts.RemoveAll(a => a.Id == account.Id); }))
        {
            RefreshAccounts();
            StatusText.Text = "تم حذف الحساب.";
        }
    }

    private bool TryChange(Action change)
    {
        if (_session is null) return false;
        var oldApplications = _session.Data.Applications.Select(a => new ApplicationEntry { Id = a.Id, Name = a.Name, Icon = a.Icon }).ToList();
        var oldAccounts = _session.Data.Accounts.Select(a => new AccountEntry
        {
            Id = a.Id, ApplicationId = a.ApplicationId, Name = a.Name, Username = a.Username,
            Phone = a.Phone, Email = a.Email, Password = a.Password, Notes = a.Notes
        }).ToList();
        try
        {
            change();
            _store.Save(_session);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or JsonException)
        {
            _session.Data.Applications = oldApplications;
            _session.Data.Accounts = oldAccounts;
            RefreshApplications();
            MessageBox.Show(this, "تعذّر حفظ التغيير. أُعيدت البيانات إلى حالتها السابقة، والملف المحفوظ لم يتغير.\n" + ex.Message,
                "فشل الحفظ", MessageBoxButton.OK, MessageBoxImage.Error);
            return false;
        }
    }

    private void TogglePasswords_Click(object sender, RoutedEventArgs e)
    {
        _showPasswords = !_showPasswords;
        if (sender is Button button) button.Content = _showPasswords ? "إخفاء كلمات المرور" : "إظهار كلمات المرور";
        RefreshAccounts();
    }

    private void CopyPassword_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedAccount is not { } account) { NoAccountSelected(); return; }
        if (account.Password.Length == 0)
        {
            MessageBox.Show(this, "لا توجد كلمة مرور محفوظة لهذا الحساب.", "لا توجد كلمة مرور",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            Clipboard.SetText(account.Password);
            _clipboardSecret = account.Password;
            _clipboardTimer.Stop();
            _clipboardTimer.Start();
            StatusText.Text = "تم نسخ كلمة المرور؛ ستُمسح من الحافظة بعد 30 ثانية.";
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.ExternalException or InvalidOperationException)
        {
            MessageBox.Show(this, "تعذّر نسخ كلمة المرور إلى الحافظة. حاول مرة أخرى.", "تعذّر النسخ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void CopyEmail_Click(object sender, RoutedEventArgs e) => CopyField(a => a.Email, "البريد الإلكتروني");
    private void CopyUsername_Click(object sender, RoutedEventArgs e) => CopyField(a => a.Username, "اسم المستخدم");

    private void CopyOtherField_Click(object sender, RoutedEventArgs e)
    {
        var menu = new ContextMenu();
        menu.Items.Add(CreateCopyMenuItem("الاسم", a => a.Name));
        menu.Items.Add(CreateCopyMenuItem("رقم الهاتف", a => a.Phone));
        menu.Items.Add(CreateCopyMenuItem("الملاحظات", a => a.Notes));
        menu.PlacementTarget = sender as UIElement;
        menu.IsOpen = true;
    }

    private MenuItem CreateCopyMenuItem(string label, Func<AccountEntry, string> getter)
    {
        var item = new MenuItem { Header = label };
        item.Click += (_, _) => CopyField(getter, label);
        return item;
    }

    private void CopyField(Func<AccountEntry, string> field, string label)
    {
        if (SelectedAccount is not { } account) { NoAccountSelected(); return; }
        if (string.IsNullOrEmpty(field(account)))
        {
            MessageBox.Show(this, $"لا توجد قيمة محفوظة في حقل {label}.", "حقل فارغ",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            Clipboard.SetText(field(account));
            StatusText.Text = $"تم نسخ {label}.";
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.ExternalException or InvalidOperationException)
        {
            MessageBox.Show(this, "تعذّر النسخ إلى الحافظة. حاول مرة أخرى.", "تعذّر النسخ", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ClipboardTimer_Tick(object? sender, EventArgs e) => ClearOwnedClipboard();

    private void ClearOwnedClipboard()
    {
        _clipboardTimer.Stop();
        if (_clipboardSecret is null) return;
        try
        {
            if (Clipboard.ContainsText() && Clipboard.GetText() == _clipboardSecret)
            {
                Clipboard.Clear();
                StatusText.Text = "تم مسح كلمة المرور من الحافظة.";
            }
        }
        catch (Exception ex) when (ex is System.Runtime.InteropServices.ExternalException or InvalidOperationException)
        {
            StatusText.Text = "تعذّر مسح الحافظة تلقائيًا. امسحها يدويًا إن لزم.";
        }
        finally { _clipboardSecret = null; }
    }

    private void NoAccountSelected() =>
        MessageBox.Show(this, "اختر حسابًا من الجدول أولًا.", "لا يوجد حساب محدد", MessageBoxButton.OK, MessageBoxImage.Information);

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null) return;
        var window = new Window
        {
            Owner = this, Title = "الإعدادات", Width = 600, Height = 690, MinWidth = 480,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = new SolidColorBrush(Color.FromRgb(245, 247, 250)),
            FlowDirection = FlowDirection.RightToLeft
        };
        var panel = new StackPanel { Margin = new Thickness(22) };
        panel.Children.Add(new TextBlock { Text = "إعدادات PassVault", FontSize = 22, FontWeight = FontWeights.SemiBold, Margin = new Thickness(4, 0, 4, 10) });
        AddSettingButton(panel, "تغيير كلمة المرور الرئيسية", () => ChangeMasterPassword(window));
        AddSettingButton(panel, "إنشاء نسخة احتياطية مشفّرة", () => CreateBackup(window));
        AddSettingButton(panel, "استعادة نسخة احتياطية", () => RestoreBackup(window));
        AddSettingButton(panel, "تصدير الحسابات إلى PDF", () => ExportPdf(window));
        panel.Children.Add(new TextBlock { Text = "القفل التلقائي بعد (دقيقة)", FontWeight = FontWeights.SemiBold, Margin = new Thickness(6, 14, 6, 0) });
        var idleInput = new TextBox { Text = ReadIdleMinutes().ToString(), Width = 120, HorizontalAlignment = HorizontalAlignment.Right };
        panel.Children.Add(idleInput);
        AddSettingButton(panel, "حفظ مدة القفل (1–120 دقيقة)", () =>
        {
            if (!int.TryParse(idleInput.Text, out var minutes) || minutes is < 1 or > 120)
            {
                MessageBox.Show(window, "أدخل عددًا صحيحًا بين 1 و120 دقيقة.", "قيمة غير صالحة", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            try
            {
                _store.SaveIdleMinutes(minutes);
                StatusText.Text = $"تم ضبط القفل التلقائي بعد {minutes} دقيقة.";
                MessageBox.Show(window, "تم حفظ مدة القفل التلقائي.", "تم الحفظ", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                MessageBox.Show(window, "تعذّر حفظ الإعداد. تحقق من صلاحيات مجلد بيانات التطبيق.\n" + ex.Message,
                    "فشل حفظ الإعداد", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        });
        panel.Children.Add(new TextBlock { Text = "مسار ملف الخزنة المشفّر", FontWeight = FontWeights.SemiBold, Margin = new Thickness(6, 14, 6, 0) });
        var path = new TextBox { Text = _store.VaultPath, IsReadOnly = true, TextWrapping = TextWrapping.Wrap, MinHeight = 48 };
        panel.Children.Add(path);
        AddSettingButton(panel, "فتح مجلد البيانات", () =>
        {
            try
            {
                Directory.CreateDirectory(_store.DataDirectory);
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(_store.DataDirectory) { UseShellExecute = true });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                MessageBox.Show(window, "تعذّر فتح مجلد البيانات.\n" + ex.Message, "خطأ", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        });
        var includePasswords = new CheckBox
        {
            Content = "تضمين كلمات المرور في PDF (معطّل افتراضيًا)",
            IsChecked = _includePasswordsInPdf, Margin = new Thickness(8, 14, 8, 4), FontWeight = FontWeights.SemiBold
        };
        includePasswords.Checked += (_, _) => _includePasswordsInPdf = true;
        includePasswords.Unchecked += (_, _) => _includePasswordsInPdf = false;
        panel.Children.Add(includePasswords);
        panel.Children.Add(new TextBlock
        {
            Text = "تُحفظ الخزنة والنسخ الاحتياطية في مجلد AppData المحلي للمستخدم. لا تُزامن PassVault هذه الملفات إلى أي خادم.",
            TextWrapping = TextWrapping.Wrap, Foreground = new SolidColorBrush(Color.FromRgb(115, 128, 150)), Margin = new Thickness(8, 8, 8, 4)
        });
        panel.Children.Add(new TextBlock
        {
            Text = "تحذير: نسيان كلمة المرور الرئيسية يمنع استعادة الخزنة والنسخ الاحتياطية المشفّرة.",
            TextWrapping = TextWrapping.Wrap, Foreground = new SolidColorBrush(Color.FromRgb(163, 59, 55)), Margin = new Thickness(8, 4, 8, 4)
        });
        AddSettingButton(panel, "إغلاق", window.Close);
        window.Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        window.ShowDialog();
    }

    private static void AddSettingButton(Panel panel, string title, Action action)
    {
        var button = new Button { Content = title, HorizontalContentAlignment = HorizontalAlignment.Right, Margin = new Thickness(4, 5, 4, 5) };
        button.Click += (_, _) => action();
        panel.Children.Add(button);
    }

    private void ChangeMasterPassword(Window owner)
    {
        var oldPassword = DialogFactory.PromptPassword(owner, "تغيير كلمة المرور", "أدخل كلمة المرور الحالية للتأكيد.");
        if (oldPassword is null) return;
        try
        {
            using var verified = _store.Unlock(oldPassword);
        }
        catch (CryptographicException)
        {
            MessageBox.Show(owner, "كلمة المرور الحالية غير صحيحة؛ لم يتم تغيير أي بيانات.", "تعذّر التحقق",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            MessageBox.Show(owner, "تعذّر التحقق من كلمة المرور الحالية.\n" + ex.Message, "تعذّر التحقق",
                MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var window = new Window
        {
            Owner = owner, Title = "كلمة مرور رئيسية جديدة", Width = 440, Height = 300,
            WindowStartupLocation = WindowStartupLocation.CenterOwner, Background = new SolidColorBrush(Color.FromRgb(245, 247, 250)),
            FlowDirection = FlowDirection.RightToLeft
        };
        var panel = new StackPanel { Margin = new Thickness(20) };
        panel.Children.Add(new TextBlock { Text = "استخدم عبارة طويلة وفريدة؛ لا يمكن استعادة بياناتك إذا نسيتها.", TextWrapping = TextWrapping.Wrap, Margin = new Thickness(4) });
        panel.Children.Add(new TextBlock { Text = "كلمة المرور الجديدة", Margin = new Thickness(4, 8, 4, 0) });
        var first = new PasswordBox { Margin = new Thickness(4), Padding = new Thickness(10, 8, 10, 8) };
        panel.Children.Add(first);
        panel.Children.Add(new TextBlock { Text = "تأكيد كلمة المرور", Margin = new Thickness(4, 8, 4, 0) });
        var second = new PasswordBox { Margin = new Thickness(4), Padding = new Thickness(10, 8, 10, 8) };
        panel.Children.Add(second);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 14, 0, 0) };
        var save = new Button { Content = "تغيير كلمة المرور", Background = new SolidColorBrush(Color.FromRgb(72, 103, 214)), Foreground = Brushes.White };
        var cancel = new Button { Content = "إلغاء", IsCancel = true };
        buttons.Children.Add(save);
        buttons.Children.Add(cancel);
        panel.Children.Add(buttons);
        save.Click += (_, _) =>
        {
            if (first.Password.Length < 8)
            {
                MessageBox.Show(window, "استخدم 8 أحرف على الأقل، ويفضّل عبارة طويلة وفريدة.", "كلمة المرور قصيرة",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            if (first.Password != second.Password)
            {
                MessageBox.Show(window, "كلمتا المرور غير متطابقتين.", "تحقق من الإدخال", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            try
            {
                var replacement = _store.ChangePassword(_session!, first.Password);
                _session!.Dispose();
                _session = replacement;
                StatusText.Text = "تم تغيير كلمة المرور وإعادة تشفير الخزنة.";
                MessageBox.Show(window, "تم تغيير كلمة المرور وإعادة تشفير بياناتك بنجاح.", "اكتمل التغيير",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                window.DialogResult = true;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
            {
                MessageBox.Show(window, "فشل تغيير كلمة المرور؛ بقيت الخزنة الحالية دون تغيير.\n" + ex.Message,
                    "تعذّر التغيير", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        };
        window.Content = panel;
        window.ShowDialog();
    }

    private void CreateBackup(Window owner)
    {
        var dialog = new SaveFileDialog { Title = "إنشاء نسخة احتياطية مشفّرة", Filter = "نسخة PassVault مشفّرة (*.pv)|*.pv", DefaultExt = ".pv", AddExtension = true };
        if (dialog.ShowDialog(owner) != true) return;
        try
        {
            _store.CreateBackup(dialog.FileName);
            StatusText.Text = "تم إنشاء نسخة احتياطية مشفّرة.";
            MessageBox.Show(owner, "تم إنشاء نسخة احتياطية مشفّرة. احتفظ بها في مكان آمن؛ يلزم استخدام كلمة المرور الرئيسية لاستعادتها.",
                "اكتمل النسخ الاحتياطي", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(owner, "تعذّر إنشاء النسخة الاحتياطية.\n" + ex.Message, "فشل النسخ الاحتياطي",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RestoreBackup(Window owner)
    {
        var dialog = new OpenFileDialog { Title = "اختيار نسخة PassVault", Filter = "نسخ PassVault (*.pv)|*.pv|كل الملفات (*.*)|*.*", CheckFileExists = true };
        if (dialog.ShowDialog(owner) != true) return;
        if (MessageBox.Show(owner, "سيتم استبدال الخزنة الحالية بالنسخة المختارة. أنشئ نسخة احتياطية من بياناتك الحالية قبل المتابعة. هل تريد الاستمرار؟",
                "تأكيد الاستعادة", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        var password = DialogFactory.PromptPassword(owner, "التحقق من النسخة", "أدخل كلمة المرور الرئيسية التي استُخدمت لإنشاء هذه النسخة.");
        if (password is null) return;
        try
        {
            var restored = _store.Restore(dialog.FileName, password);
            _session!.Dispose();
            _session = restored;
            _selectedApplicationId = null;
            RefreshApplications();
            StatusText.Text = "تم التحقق من النسخة واستعادتها بنجاح.";
            MessageBox.Show(owner, "تم التحقق من النسخة واستعادة البيانات بنجاح.", "اكتملت الاستعادة",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (CryptographicException)
        {
            MessageBox.Show(owner, "كلمة المرور غير صحيحة لهذه النسخة أو أن الملف تالف. لم تتغير الخزنة الحالية.",
                "تعذّرت الاستعادة", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            MessageBox.Show(owner, "النسخة غير صالحة أو تعذّر استبدال الخزنة. بقيت البيانات الحالية كما هي.\n" + ex.Message,
                "تعذّرت الاستعادة", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExportPdf(Window owner)
    {
        if (_session is null) return;
        if (_includePasswordsInPdf &&
            MessageBox.Show(owner, "سيحتوي ملف PDF على كلمات مرورك. يمكن فتح ملف PDF دون كلمة مرور PassVault، وقد يبقى بعد انتهاء الطباعة. لا تشاركه إلا عبر قناة آمنة. هل تريد المتابعة؟",
                "بيانات حساسة في PDF", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        if (!_includePasswordsInPdf &&
            MessageBox.Show(owner, "سيحتوي ملف PDF على أسماء المستخدمين والبريد والبيانات الأخرى، لكنه لن يتضمن كلمات المرور. اختر طابعة Microsoft Print to PDF لحفظه كملف.",
                "تصدير بيانات حساسة", MessageBoxButton.OKCancel, MessageBoxImage.Information) != MessageBoxResult.OK) return;
        try
        {
            var document = new FlowDocument
            {
                FlowDirection = FlowDirection.RightToLeft,
                FontFamily = new FontFamily("Segoe UI"),
                FontSize = 11,
                PagePadding = new Thickness(48),
                ColumnWidth = 700
            };
            document.Blocks.Add(new Paragraph(new Run("PassVault — بيانات الحسابات"))
            {
                FontSize = 18, FontWeight = FontWeights.Bold, TextAlignment = TextAlignment.Right,
                Margin = new Thickness(0, 0, 0, 16)
            });
            foreach (var app in _session.Data.Applications.OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                var accounts = _session.Data.Accounts.Where(a => a.ApplicationId == app.Id)
                    .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase);
                document.Blocks.Add(new Paragraph(new Run($"{app.Icon}  {app.Name}"))
                {
                    FontSize = 14, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 10, 0, 5)
                });
                foreach (var account in accounts)
                {
                    var fields = new List<string>
                    {
                        $"الاسم: {account.Name}", $"اسم المستخدم: {account.Username}",
                        $"الهاتف: {account.Phone}", $"البريد الإلكتروني: {account.Email}"
                    };
                    if (_includePasswordsInPdf) fields.Add($"كلمة المرور: {account.Password}");
                    if (!string.IsNullOrWhiteSpace(account.Notes)) fields.Add($"ملاحظات: {account.Notes}");
                    document.Blocks.Add(new Paragraph(new Run(string.Join("    |    ", fields)))
                    {
                        Margin = new Thickness(8, 2, 8, 8), TextAlignment = TextAlignment.Right
                    });
                }
            }
            var print = new PrintDialog();
            if (print.ShowDialog() == true)
                print.PrintDocument(((IDocumentPaginatorSource)document).DocumentPaginator, "PassVault - Accounts");
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Printing.PrintSystemException or IOException)
        {
            MessageBox.Show(owner, "تعذّر إنشاء أو إرسال مستند PDF إلى الطابعة. تحقق من تثبيت طابعة Microsoft Print to PDF.\n" + ex.Message,
                "فشل تصدير PDF", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
