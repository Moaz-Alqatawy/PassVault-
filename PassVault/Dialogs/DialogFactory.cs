using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using PassVault.Models;

namespace PassVault.Dialogs;

public static class DialogFactory
{
    public static AccountEntry? EditAccount(Window owner, AccountEntry? original, Guid applicationId)
    {
        var window = CreateDialog(owner, original is null ? "إضافة حساب" : "تعديل الحساب", 500, 720);
        var panel = NewForm();
        var name = AddTextField(panel, "الاسم", original?.Name);
        var username = AddTextField(panel, "اسم المستخدم", original?.Username);
        var phone = AddTextField(panel, "رقم الهاتف", original?.Phone);
        var email = AddTextField(panel, "البريد الإلكتروني", original?.Email);
        var password = AddPasswordField(panel, "كلمة المرور", original?.Password);
        var notes = AddTextField(panel, "ملاحظات (اختياري)", original?.Notes, multiline: true);

        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Left };
        var generate = new Button { Content = "توليد كلمة مرور" };
        generate.Click += (_, _) =>
        {
            var generated = GeneratePassword(owner);
            if (generated is not null) password.Password = generated;
        };
        var save = new Button { Content = "حفظ", Background = Brush("#4867D6"), Foreground = Brush("White") };
        var cancel = new Button { Content = "إلغاء" };
        buttons.Children.Add(save);
        buttons.Children.Add(cancel);
        buttons.Children.Add(generate);
        panel.Children.Add(buttons);

        AccountEntry? result = null;
        save.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(name.Text))
            {
                MessageBox.Show(window, "يرجى إدخال اسم الحساب.", "بيانات ناقصة", MessageBoxButton.OK, MessageBoxImage.Information);
                name.Focus();
                return;
            }
            result = new AccountEntry
            {
                Id = original?.Id ?? Guid.NewGuid(),
                ApplicationId = applicationId,
                Name = name.Text.Trim(),
                Username = username.Text.Trim(),
                Phone = phone.Text.Trim(),
                Email = email.Text.Trim(),
                Password = password.Password,
                Notes = notes.Text.Trim()
            };
            window.DialogResult = true;
        };
        cancel.Click += (_, _) => window.DialogResult = false;
        window.Content = new ScrollViewer { Content = panel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        return window.ShowDialog() == true ? result : null;
    }

    public static ApplicationEntry? AddApplication(Window owner)
    {
        var window = CreateDialog(owner, "إضافة تطبيق", 390, 310);
        var panel = NewForm();
        var name = AddTextField(panel, "اسم التطبيق");
        var icon = AddTextField(panel, "أيقونة أو رمز تعبيري", "🔐");
        panel.Children.Add(new TextBlock
        {
            Text = "مثال: بريد العمل ✉ أو منصة اجتماعية 🌐",
            Margin = new Thickness(6, 0, 6, 8),
            Foreground = Brush("#738096")
        });
        var buttons = AddButtons(panel);
        var save = new Button { Content = "إضافة", Background = Brush("#4867D6"), Foreground = Brush("White") };
        buttons.Children.Add(save);
        buttons.Children.Add(new Button { Content = "إلغاء", IsCancel = true });
        ApplicationEntry? result = null;
        save.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(name.Text))
            {
                MessageBox.Show(window, "يرجى إدخال اسم التطبيق.", "بيانات ناقصة", MessageBoxButton.OK, MessageBoxImage.Information);
                name.Focus();
                return;
            }
            result = new ApplicationEntry { Name = name.Text.Trim(), Icon = string.IsNullOrWhiteSpace(icon.Text) ? "🔐" : icon.Text.Trim() };
            window.DialogResult = true;
        };
        window.Content = panel;
        return window.ShowDialog() == true ? result : null;
    }

    public static string? PromptPassword(Window owner, string title, string message)
    {
        var window = CreateDialog(owner, title, 420, 230);
        var panel = NewForm();
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(6, 0, 6, 8) });
        var password = new PasswordBox { Margin = new Thickness(4), Padding = new Thickness(10, 8, 10, 8) };
        panel.Children.Add(password);
        var buttons = AddButtons(panel);
        var ok = new Button { Content = "متابعة", Background = Brush("#4867D6"), Foreground = Brush("White") };
        var cancel = new Button { Content = "إلغاء", IsCancel = true };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        ok.Click += (_, _) =>
        {
            if (password.Password.Length == 0)
            {
                MessageBox.Show(window, "أدخل كلمة المرور للمتابعة.", "مطلوب", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            window.DialogResult = true;
        };
        window.Content = panel;
        window.Loaded += (_, _) => password.Focus();
        return window.ShowDialog() == true ? password.Password : null;
    }

    private static string? GeneratePassword(Window owner)
    {
        var window = CreateDialog(owner, "مولّد كلمات المرور", 420, 410);
        var panel = NewForm();
        var lengthBox = AddTextField(panel, "الطول (8 إلى 128)", "20");
        var upper = AddCheck(panel, "أحرف كبيرة (A-Z)", true);
        var lower = AddCheck(panel, "أحرف صغيرة (a-z)", true);
        var digits = AddCheck(panel, "أرقام (0-9)", true);
        var symbols = AddCheck(panel, "رموز خاصة", true);
        var resultBox = new TextBox { IsReadOnly = true, Margin = new Thickness(4), Padding = new Thickness(10) };
        panel.Children.Add(resultBox);
        var buttons = AddButtons(panel);
        var generate = new Button { Content = "توليد" };
        var use = new Button { Content = "استخدام كلمة المرور", Background = Brush("#4867D6"), Foreground = Brush("White") };
        buttons.Children.Add(generate);
        buttons.Children.Add(use);
        buttons.Children.Add(new Button { Content = "إلغاء", IsCancel = true });
        generate.Click += (_, _) =>
        {
            if (!int.TryParse(lengthBox.Text, out var length) || length is < 8 or > 128)
            {
                MessageBox.Show(window, "أدخل طولًا صحيحًا بين 8 و128.", "طول غير صالح", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            var sets = new List<string>();
            if (upper.IsChecked == true) sets.Add("ABCDEFGHJKLMNPQRSTUVWXYZ");
            if (lower.IsChecked == true) sets.Add("abcdefghijkmnopqrstuvwxyz");
            if (digits.IsChecked == true) sets.Add("23456789");
            if (symbols.IsChecked == true) sets.Add("!@#$%^&*()-_=+[]{};:,.?");
            if (sets.Count == 0)
            {
                MessageBox.Show(window, "اختر نوعًا واحدًا على الأقل من الأحرف.", "اختيار مطلوب", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            resultBox.Text = SecurePassword(length, sets);
        };
        string? result = null;
        use.Click += (_, _) =>
        {
            if (resultBox.Text.Length == 0)
            {
                MessageBox.Show(window, "ولّد كلمة المرور أولًا.", "لا توجد كلمة مرور", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            result = resultBox.Text;
            window.DialogResult = true;
        };
        window.Content = panel;
        return window.ShowDialog() == true ? result : null;
    }

    private static string SecurePassword(int length, IReadOnlyList<string> sets)
    {
        var chars = new char[length];
        var all = string.Concat(sets);
        for (var i = 0; i < sets.Count; i++) chars[i] = sets[i][RandomNumberGenerator.GetInt32(sets[i].Length)];
        for (var i = sets.Count; i < length; i++) chars[i] = all[RandomNumberGenerator.GetInt32(all.Length)];
        for (var i = chars.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        return new string(chars);
    }

    private static TextBox AddTextField(Panel panel, string label, string? value = null, bool multiline = false)
    {
        panel.Children.Add(new TextBlock { Text = label, Margin = new Thickness(6, 8, 6, 0), FontWeight = FontWeights.SemiBold });
        var box = new TextBox { Text = value ?? "", AcceptsReturn = multiline, TextWrapping = multiline ? TextWrapping.Wrap : TextWrapping.NoWrap };
        if (multiline) box.Height = 90;
        panel.Children.Add(box);
        return box;
    }

    private static PasswordBox AddPasswordField(Panel panel, string label, string? value)
    {
        panel.Children.Add(new TextBlock { Text = label, Margin = new Thickness(6, 8, 6, 0), FontWeight = FontWeights.SemiBold });
        var box = new PasswordBox { Password = value ?? "" };
        panel.Children.Add(box);
        return box;
    }

    private static CheckBox AddCheck(Panel panel, string text, bool initial)
    {
        var check = new CheckBox { Content = text, IsChecked = initial, Margin = new Thickness(8, 7, 8, 3) };
        panel.Children.Add(check);
        return check;
    }

    private static StackPanel AddButtons(Panel panel)
    {
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 12, 0, 0) };
        panel.Children.Add(buttons);
        return buttons;
    }

    private static StackPanel NewForm() => new() { Margin = new Thickness(20), FlowDirection = FlowDirection.RightToLeft };

    private static Window CreateDialog(Window owner, string title, double width, double height) => new()
    {
        Owner = owner,
        Title = title,
        Width = width,
        Height = height,
        MinWidth = width,
        WindowStartupLocation = WindowStartupLocation.CenterOwner,
        ResizeMode = ResizeMode.CanResize,
        Background = Brush("#F5F7FA"),
        FlowDirection = FlowDirection.RightToLeft,
        FontFamily = new System.Windows.Media.FontFamily("Segoe UI")
    };

    private static System.Windows.Media.SolidColorBrush Brush(string color) =>
        new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(color));
}
