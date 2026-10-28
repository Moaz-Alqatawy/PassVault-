using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PassVault.Models;

namespace PassVault.Security;

public sealed class VaultCrypto
{
    public const int CurrentIterations = 600_000;
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    public VaultSession Create(string masterPassword)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var key = DeriveKey(masterPassword, salt, CurrentIterations);
        var session = new VaultSession(new VaultData(), key, salt, CurrentIterations);
        return session;
    }

    public VaultSession Decrypt(string masterPassword, string envelopeJson)
    {
        EncryptedEnvelope envelope;
        byte[] salt;
        byte[] nonce;
        byte[] tag;
        byte[] ciphertext;
        try
        {
            envelope = JsonSerializer.Deserialize<EncryptedEnvelope>(envelopeJson)
                ?? throw new InvalidDataException("ملف الخزنة غير صالح.");
            if (envelope.Version != 1 || envelope.Iterations < 100_000 || envelope.Iterations > 2_000_000 ||
                string.IsNullOrEmpty(envelope.Salt) || string.IsNullOrEmpty(envelope.Nonce) ||
                string.IsNullOrEmpty(envelope.Tag) || string.IsNullOrEmpty(envelope.Ciphertext))
                throw new InvalidDataException("تنسيق ملف الخزنة غير مدعوم أو تالف.");
            salt = Convert.FromBase64String(envelope.Salt);
            nonce = Convert.FromBase64String(envelope.Nonce);
            tag = Convert.FromBase64String(envelope.Tag);
            ciphertext = Convert.FromBase64String(envelope.Ciphertext);
            if (salt.Length != SaltSize || nonce.Length != NonceSize || tag.Length != TagSize)
                throw new InvalidDataException("تنسيق ملف الخزنة غير مدعوم أو تالف.");
        }
        catch (JsonException ex) { throw new InvalidDataException("ملف الخزنة غير صالح.", ex); }
        catch (FormatException ex) { throw new InvalidDataException("ملف الخزنة غير صالح.", ex); }

        var key = DeriveKey(masterPassword, salt, envelope.Iterations);
        byte[]? plaintext = null;
        try
        {
            plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext);
            var data = JsonSerializer.Deserialize<VaultData>(plaintext, JsonOptions)
                ?? throw new InvalidDataException("بيانات الخزنة غير صالحة.");
            if (data.Applications is null || data.Accounts is null ||
                data.Applications.Any(app => app is null || string.IsNullOrWhiteSpace(app.Name) || app.Icon is null) ||
                data.Accounts.Any(account => account is null || account.Name is null || account.Username is null ||
                    account.Phone is null || account.Email is null || account.Password is null || account.Notes is null))
                throw new InvalidDataException("بيانات الخزنة غير صالحة.");
            return new VaultSession(data, key, salt, envelope.Iterations);
        }
        catch (JsonException ex)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new InvalidDataException("بيانات الخزنة غير صالحة.", ex);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            throw;
        }
        finally
        {
            if (plaintext is not null) CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public string Encrypt(VaultSession session)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(session.Data, JsonOptions);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];
        using (var aes = new AesGcm(session.Key, TagSize))
            aes.Encrypt(nonce, plaintext, ciphertext, tag);
        CryptographicOperations.ZeroMemory(plaintext);
        return JsonSerializer.Serialize(new EncryptedEnvelope
        {
            Version = 1,
            Iterations = session.Iterations,
            Salt = Convert.ToBase64String(session.Salt),
            Nonce = Convert.ToBase64String(nonce),
            Tag = Convert.ToBase64String(tag),
            Ciphertext = Convert.ToBase64String(ciphertext)
        });
    }

    public VaultSession ChangePassword(VaultSession current, string newPassword)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        return new VaultSession(current.Data, DeriveKey(newPassword, salt, CurrentIterations), salt, CurrentIterations);
    }

    private static byte[] DeriveKey(string password, byte[] salt, int iterations)
    {
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        try { return Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, iterations, HashAlgorithmName.SHA256, 32); }
        finally { CryptographicOperations.ZeroMemory(passwordBytes); }
    }

    private sealed class EncryptedEnvelope
    {
        public int Version { get; set; }
        public int Iterations { get; set; }
        public string Salt { get; set; } = "";
        public string Nonce { get; set; } = "";
        public string Tag { get; set; } = "";
        public string Ciphertext { get; set; } = "";
    }
}

public sealed class VaultSession(VaultData data, byte[] key, byte[] salt, int iterations) : IDisposable
{
    public VaultData Data { get; } = data;
    public byte[] Key { get; } = key;
    public byte[] Salt { get; } = salt;
    public int Iterations { get; } = iterations;

    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(Key);
        CryptographicOperations.ZeroMemory(Salt);
    }
}
