namespace Frends.LDAP.AddUserToGroups.Tests;

using NUnit.Framework;
using Frends.LDAP.AddUserToGroups.Definitions;
using Novell.Directory.Ldap;
using System.Threading.Tasks;
using System.Threading;

[TestFixture]
public class UnitTests
{
    /*
        LDAP server to docker.
        docker run -d -it --rm -p 10389:10389 dwimberger/ldap-ad-it
    */
    private readonly string? _host = "127.0.0.1";
    private readonly int _port = 10389;
    private readonly string? _user = "uid=admin,ou=system";
    private readonly string? _pw = "secret";
    private readonly string? _groupDn = "cn=admin,ou=roles,dc=wimpi,dc=net";
    private readonly string _testUserDn = "CN=Test User,ou=users,dc=wimpi,dc=net";

    private Input? input;
    private Connection? connection;

    [SetUp]
    public async Task SetUp()
    {
        connection = new()
        {
            Host = _host,
            User = _user,
            Password = _pw,
            SecureSocketLayer = false,
            Port = _port,
            TLS = false,
        };

        await CreateTestUser(_testUserDn);
    }

    [TearDown]
    public async Task Teardown()
    {
        await DeleteTestUsers(_testUserDn, "CN=admin,ou=roles,dc=wimpi,dc=net");
    }

    [Test]
    public async Task Update_HandleLDAPError_Test()
    {
        input = new()
        {
            UserDistinguishedName = "CN=Common Name,CN=Users,DC=Example,DC=Com",
            GroupDistinguishedName = "CN=Admins,DC=Example,DC=Com",
            UserExistsAction = UserExistsAction.Throw,
        };

        var ex = Assert.ThrowsAsync<Exception>(async () => await LDAP.AddUserToGroups(input, connection, default));
        Assert.That(ex.Message.Contains("No Such Object"), Is.True, "Expected exception message to contain 'No Such Object'.");
    }

    [Test]
    public async Task AddUserToGroups_Test()
    {
        input = new()
        {
            UserDistinguishedName = _testUserDn,
            GroupDistinguishedName = _groupDn,
            UserExistsAction = UserExistsAction.Throw,
        };

        var result = await LDAP.AddUserToGroups(input, connection, default);
        Assert.That(result.Success, Is.True, "Expected result.Success to be true.");
    }

    [Test]
    public async Task AddUserToGroups_TestWithUserExisting()
    {
        input = new()
        {
            UserDistinguishedName = _testUserDn,
            GroupDistinguishedName = _groupDn,
            UserExistsAction = UserExistsAction.Throw,
        };

        var result = await LDAP.AddUserToGroups(input, connection, default);
        Assert.That(result.Success, Is.True, "Expected result.Success to be true.");

        var ex = Assert.ThrowsAsync<Exception>(async () => await LDAP.AddUserToGroups(input, connection, default));
        Assert.That(ex.Message.Contains("Attribute Or Value Exists"), Is.True, "Expected exception message to contain 'Attribute Or Value Exists'.");
    }

    [Test]
    public async Task AddUserToGroups_TestWithUserExistingWithSkip()
    {
        input = new()
        {
            UserDistinguishedName = _testUserDn,
            GroupDistinguishedName = _groupDn,
            UserExistsAction = UserExistsAction.Skip,
        };

        var result = await LDAP.AddUserToGroups(input, connection, default);
        Assert.That(result.Success, Is.True, "Expected result.Success to be true.");

        input.UserExistsAction = UserExistsAction.Skip;

        result = await LDAP.AddUserToGroups(input, connection, default);
        Assert.That(result.Success, Is.False, "Expected result.Success to be false when skipping existing user.");
    }

    private async Task CreateTestUser(string userDn)
    {
        using LdapConnection conn = new()
        {
            SecureSocketLayer = false,
        };
        await conn.ConnectAsync(_host, _port, CancellationToken.None);
        await conn.BindAsync(_user, _pw, CancellationToken.None);

        // Check if user already exists to avoid exception
        try
        {
            var search = await conn.SearchAsync(
                userDn,
                LdapConnection.ScopeBase,
                "(objectClass=inetOrgPerson)",
                null,
                false,
                CancellationToken.None
            );
            if (await search.HasMoreAsync(CancellationToken.None))
            {
                conn.Disconnect();
                return; // User already exists, skip creation
            }
        }
        catch
        {
            // User does not exist, continue to create
        }

        var attributeSet = new LdapAttributeSet
        {
            new LdapAttribute("objectclass", "inetOrgPerson"),
            new LdapAttribute("cn", "Test User"),
            new LdapAttribute("givenname", "Test"),
            new LdapAttribute("sn", "User"),
        };

        LdapEntry newEntry = new(userDn, attributeSet);
        try
        {
            await conn.AddAsync(newEntry, CancellationToken.None);
        }
        catch (LdapException ex) when (ex.ResultCode == LdapException.EntryAlreadyExists)
        {
            // Ignore if already exists
        }
        conn.Disconnect();
    }

    private async Task DeleteTestUsers(string userDn, string groupDn)
    {
        using LdapConnection conn = new();
        await conn.ConnectAsync(_host, _port, CancellationToken.None);
        await conn.BindAsync(_user, _pw, CancellationToken.None);

        try
        {
            var searchResults = await conn.SearchAsync(
                    groupDn,
                    LdapConnection.ScopeSub,
                    "(objectClass=*)",
                    null,
                    false,
                    CancellationToken.None);

            if (await searchResults.HasMoreAsync(CancellationToken.None))
            {
                LdapEntry groupEntry = await searchResults.NextAsync();
                LdapAttribute memberAttr = groupEntry.Get("member");
                if (memberAttr != null)
                {
                    var currentMembers = memberAttr.StringValueArray;
                    if (currentMembers.Any(e => e == userDn))
                    {
                        // Remove the user from the group
                        var mod = new LdapModification(LdapModification.Delete, new LdapAttribute("member", userDn));
                        try
                        {
                            await conn.ModifyAsync(groupDn, new[] { mod }, CancellationToken.None);
                        }
                        catch (LdapException) { /* Ignore if already removed */ }
                    }
                }
            }
        }
        catch (LdapException) { /* Ignore group not found */ }

        // Try to delete the user, ignore if not found
        try
        {
            await conn.DeleteAsync(userDn, CancellationToken.None);
        }
        catch (LdapException) { /* Ignore if user does not exist */ }

        conn.Disconnect();
    }
}