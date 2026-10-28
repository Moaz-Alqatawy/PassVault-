using System.IO;
using System.Text;
using PassVault.Security;

namespace PassVault.Storage;

public sealed class VaultStore(VaultCrypto crypto, string? dataDirectory = null)
{
    public string DataDirectory { get; } = dataDirectory ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PassVault");
    public string VaultPath => Path.Combine(DataDirectory, "vault.pv");
    public string SettingsPath => Path.Combine(DataDirectory, "settings.json");
    public bool Exists => File.Exists(VaultPath);

    public VaultSession Create(string password)
    {
        Directory.CreateDirectory(DataDirectory);
        var session = crypto.Create(password);
        try { Save(session); }
        catch { session.Dispose(); throw; }
        return session;
    }

    public VaultSession Unlock(string password)
    {
        var json = File.ReadAllText(VaultPath, Encoding.UTF8);
        return crypto.Decrypt(password, json);
    }

    public void Save(VaultSession session) => AtomicWrite(VaultPath, crypto.Encrypt(session));

    public VaultSession ChangePassword(VaultSession current, string newPassword)
    {
        var replacement = crypto.ChangePassword(current, newPassword);
        try { Save(replacement); }
        catch { replacement.Dispose(); throw; }
        return replacement;
    }

    public VaultSession Restore(string backupPath, string password)
    {
        var candidate = crypto.Decrypt(password, File.ReadAllText(backupPath, Encoding.UTF8));
        try { AtomicWrite(VaultPath, crypto.Encrypt(candidate)); }
        catch { candidate.Dispose(); throw; }
        return candidate;
    }

    public void CreateBackup(string destination)
    {
        if (string.Equals(Path.GetFullPath(VaultPath), Path.GetFullPath(destination), StringComparison.OrdinalIgnoreCase))
            throw new IOException("اختر مسارًا مختلفًا عن ملف الخزنة.");
        var directory = Path.GetDirectoryName(destination)!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(destination)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var source = new FileStream(VaultPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var target = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                source.CopyTo(target);
                target.Flush(flushToDisk: true);
            }
            File.Move(temporary, destination, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    public int ReadIdleMinutes()
    {
        try
        {
            var settings = System.Text.Json.JsonSerializer.Deserialize<UserSettings>(File.ReadAllText(SettingsPath));
            if (settings is null || settings.IdleMinutes is < 1 or > 120)
                throw new InvalidDataException("إعداد مدة القفل التلقائي غير صالح.");
            return settings.IdleMinutes;
        }
        catch (FileNotFoundException) { return 5; }
        catch (System.Text.Json.JsonException ex) { throw new InvalidDataException("ملف إعدادات PassVault غير صالح.", ex); }
    }

    public void SaveIdleMinutes(int minutes)
    {
        Directory.CreateDirectory(DataDirectory);
        AtomicWrite(SettingsPath, System.Text.Json.JsonSerializer.Serialize(new UserSettings { IdleMinutes = minutes }));
    }

    private static void AtomicWrite(string path, string contents)
    {
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, $".{Path.GetFileName(path)}.{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       4096, FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
            {
                writer.Write(contents);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private sealed class UserSettings
    {
        public int IdleMinutes { get; set; } = 5;
    }
}
