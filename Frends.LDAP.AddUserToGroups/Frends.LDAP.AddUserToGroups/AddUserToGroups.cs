using Frends.LDAP.AddUserToGroups.Definitions;
using System.ComponentModel;
using Novell.Directory.Ldap;
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;
using System.Collections.Generic;

namespace Frends.LDAP.AddUserToGroups;

/// <summary>
/// LDAP task.
/// </summary>
public class LDAP
{
    /// <summary>
    /// Add user to Active Directory groups.
    /// [Documentation](https://tasks.frends.com/tasks/frends-tasks/Frends.LDAP.AddUserToGroups)
    /// </summary>
    /// <param name="input">Input parameters.</param>
    /// <param name="connection">Connection parameters.</param>
    /// <param name="cancellationToken">Cancellation token given by Frends.</param>
    /// <returns>Object { bool Success, string Error, string UserDistinguishedName, string GroupDistinguishedName }</returns>
    public static async Task<Result> AddUserToGroups([PropertyTab] Input input, [PropertyTab] Connection connection, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(connection.Host) || string.IsNullOrWhiteSpace(connection.User) || string.IsNullOrWhiteSpace(connection.Password))
            throw new Exception("AddUserToGroups error: Connection parameters missing.");

        using var conn = new LdapConnection();

        try
        {
            var defaultPort = connection.SecureSocketLayer ? 636 : 389;
            conn.SecureSocketLayer = connection.SecureSocketLayer;

            await conn.ConnectAsync(connection.Host, connection.Port == 0 ? defaultPort : connection.Port, cancellationToken);

            if (connection.TLS)
                await conn.StartTlsAsync(cancellationToken);

            await conn.BindAsync(connection.User, connection.Password, cancellationToken);

            if (await UserExistsInGroup(conn, input.UserDistinguishedName, input.GroupDistinguishedName, cancellationToken))
            {
                if (input.UserExistsAction == UserExistsAction.Skip)
                    return new Result(true, "AddUserToGroups LDAP error: User already exists in the group.", input.UserDistinguishedName, input.GroupDistinguishedName);
                // If action is Throw, we'll continue and let LDAP throw the exception
            }

            LdapAttribute member = new("member", input.UserDistinguishedName);
            LdapModification[] mods = { new LdapModification(LdapModification.Add, member) };
            await conn.ModifyAsync(input.GroupDistinguishedName, mods, cancellationToken);

            return new Result(true, null, input.UserDistinguishedName, input.GroupDistinguishedName);
        }
        catch (LdapException ex) when (ex.ResultCode == LdapException.EntryAlreadyExists)
        {
            if (input.UserExistsAction == UserExistsAction.Throw)
                throw new Exception($"AddUserToGroups LDAP error: User already exists in the group. {ex.Message}");
            return new Result(true, "AddUserToGroups LDAP error: User already exists in the group.", input.UserDistinguishedName, input.GroupDistinguishedName);
        }
        finally
        {
            if (connection.TLS) await conn.StopTlsAsync(cancellationToken);
            conn.Disconnect();
        }
    }

    private static async Task<bool> UserExistsInGroup(LdapConnection connection, string userDn, string groupDn, CancellationToken cancellationToken)
    {
        try
        {
            LdapEntry groupEntry = await connection.ReadAsync(groupDn, cancellationToken);
            LdapAttribute memberAttr = groupEntry.Get("member");

            // Check if the user is listed in the member attribute
            string[] members = memberAttr.StringValueArray;
            return members.Contains(userDn);
        }
        catch (LdapException ex) when (ex.ResultCode == LdapException.NoSuchAttribute)
        {
            // Group exists but has no member attribute, so user is probably not in the group
            return false;
        }
        catch (KeyNotFoundException ex) when (ex.Message.Contains("member"))
        {
            // Group exists but has no member attribute, so user is probably not in the group
            return false;
        }
    }
}