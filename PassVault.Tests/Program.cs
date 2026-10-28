using System.Security.Cryptography;
using System.Text.Json;
using PassVault.Models;
using PassVault.Security;
using PassVault.Storage;

var temporary = Directory.CreateTempSubdirectory("PassVault-tests-");
try
{
    var crypto = new VaultCrypto();
    var store = new VaultStore(crypto, temporary.FullName);
    using var session = store.Create("old-test-master");
    var app = new ApplicationEntry { Name = "Example" };
    session.Data.Applications.Add(app);
    session.Data.Accounts.Add(new AccountEntry
    {
        ApplicationId = app.Id, Name = "Test account", Username = "demo-user",
        Email = "demo@example.invalid", Password = "test-only-password", Notes = "non-personal test data"
    });
    store.Save(session);

    var serialized = File.ReadAllText(store.VaultPath);
    Assert(!serialized.Contains("test-only-password", StringComparison.Ordinal), "Vault must not contain account passwords in plaintext.");
    Assert(!serialized.Contains("old-test-master", StringComparison.Ordinal), "Vault must not contain the master password.");

    using (var unlocked = store.Unlock("old-test-master"))
        Assert(unlocked.Data.Accounts.Single().Password == "test-only-password", "Correct password should decrypt account data.");
    Expect<CryptographicException>(() => store.Unlock("incorrect-master"), "Incorrect password must not decrypt the vault.");

    var backupPath = Path.Combine(temporary.FullName, "backup.pv");
    store.CreateBackup(backupPath);

    var changed = store.ChangePassword(session, "new-test-master");
    session.Dispose();
    using (changed)
    {
        Expect<CryptographicException>(() => store.Unlock("old-test-master"), "Old password must stop unlocking after password change.");
        using (var unlocked = store.Unlock("new-test-master"))
            Assert(unlocked.Data.Accounts.Single().Password == "test-only-password", "Password change must preserve account data.");

        var restored = store.Restore(backupPath, "old-test-master");
        using (restored)
            Assert(restored.Data.Accounts.Single().Email == "demo@example.invalid", "Valid encrypted backup should restore.");

        var beforeInvalidRestore = File.ReadAllText(store.VaultPath);
        var invalidBackup = Path.Combine(temporary.FullName, "invalid.pv");
        File.WriteAllText(invalidBackup, "not a valid vault");
        Expect<InvalidDataException>(() => store.Restore(invalidBackup, "old-test-master"),
            "Invalid backup must be rejected before replacement.");
        Assert(File.ReadAllText(store.VaultPath) == beforeInvalidRestore, "Invalid restore must leave current vault unchanged.");

        using var afterRestore = store.Unlock("old-test-master");
        Assert(afterRestore.Data.Accounts.Single().Password == "test-only-password", "Restored vault must remain readable.");
    }

    Console.WriteLine("PassVault security/storage smoke tests passed.");
}
finally
{
    temporary.Delete(recursive: true);
}

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static void Expect<TException>(Action action, string message) where TException : Exception
{
    try { action(); }
    catch (TException) { return; }
    throw new InvalidOperationException(message);
}
