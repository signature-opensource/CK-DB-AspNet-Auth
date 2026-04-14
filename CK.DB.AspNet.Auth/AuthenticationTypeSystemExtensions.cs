using CK.Auth;
using System.Linq;
using System.Diagnostics.CodeAnalysis;

namespace CK.DB.Auth;

/// <summary>
/// Extends <see cref="IAuthenticationTypeSystem"/> objects to handle database object model.
/// </summary>
public static class AuthenticationTypeSystemExtensions
{
    /// <summary>
    /// Creates a <see cref="IUserInfo"/> from a database <see cref="IUserAuthInfo"/> object. 
    /// Must return null if o is null.
    /// </summary>
    /// <param name="this">This UserInfoType.</param>
    /// <param name="o">The user information handled by the database implementation.</param>
    /// <returns>The user info or null if o is null.</returns>
    [return: NotNullIfNotNull( nameof( o ) )]
    public static IUserInfo? FromUserAuthInfo( this IUserInfoType @this, IUserAuthInfo? o )
    {
        return o != null
                ? @this.Create(
                        o.UserId,
                        o.UserName,
                        o.Schemes.Select( x => new UserSchemeInfo( x.Name, x.LastUsed ) ).ToArray() )
                : null;
    }

}
