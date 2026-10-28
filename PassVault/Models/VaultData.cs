namespace PassVault.Models;

public sealed class VaultData
{
    public List<ApplicationEntry> Applications { get; set; } = [];
    public List<AccountEntry> Accounts { get; set; } = [];
}

public sealed class ApplicationEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Icon { get; set; } = "🔐";
}

public sealed class AccountEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ApplicationId { get; set; }
    public string Name { get; set; } = "";
    public string Username { get; set; } = "";
    public string Phone { get; set; } = "";
    public string Email { get; set; } = "";
    public string Password { get; set; } = "";
    public string Notes { get; set; } = "";
}

public sealed class AccountRow
{
    public required AccountEntry Account { get; init; }
    public required string PasswordDisplay { get; init; }
    public string Name => Account.Name;
    public string Username => Account.Username;
    public string Phone => Account.Phone;
    public string Email => Account.Email;
}
