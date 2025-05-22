﻿using System.ComponentModel;
namespace Frends.LDAP.AddUserToGroups.Definitions;

/// <summary>
/// Connection parameters.
/// </summary>
public class Connection
{
    /// <summary>
    /// Host.
    /// </summary>
    /// <example>adserver.westeurope.cloudapp.azure.com</example>
    public string Host { get; set; }

    /// <summary>
    /// Port. Value 0 = use LDAP/LDAPS default port which is 389 or 636 depending on (SecureSocketLayer) and (TLS).
    /// </summary>
    /// <example>389</example>
    [DefaultValue(0)]
    public int Port { get; set; }

    /// <summary>
    /// Do not use with TLS.
    /// </summary>
    /// <example>true</example>
    public bool SecureSocketLayer { get; set; }

    /// <summary>
    /// Connection is protected by TLS. Do not use with SecureSocketLayer.
    /// </summary>
    /// <example>true</example>
    public bool TLS { get; set; }

    /// <summary>
    /// User.
    /// </summary>
    /// <example>Foo</example>
    public string User { get; set; }

    /// <summary>
    /// Password.
    /// </summary>
    /// <example>Bar123</example>
    [PasswordPropertyText]
    public string Password { get; set; }
}