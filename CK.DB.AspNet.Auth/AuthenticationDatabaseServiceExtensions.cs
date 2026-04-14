using CK.Auth;
using System.Threading.Tasks;
using CK.AspNet.Auth;

namespace CK.DB.Auth;

/// <summary>
/// Extends <see cref="IAuthenticationDatabaseService"/> objects.
/// </summary>
public static class AuthenticationDatabaseServiceExtensions
{
    /// <summary>
    /// Helper method that calls <see cref="IAuthenticationDatabaseService.ReadUserAuthInfoAsync"/> and
    /// the <see cref="AuthenticationTypeSystemExtensions.FromUserAuthInfo"/> helper method when <paramref name="dbResult"/>
    /// is successful or returns a failed <see cref="UserLoginResult"/> based on dbResult error properties if it is on error.
    /// </summary>
    /// <param name="this">This IAuthenticationDatabaseService.</param>
    /// <param name="typeSystem">The type system to use.</param>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="dbResult">The database result to transform.</param>
    /// <returns>The (never null) UserLoginResult.</returns>
    public static async Task<UserLoginResult> CreateUserLoginResultFromDatabaseAsync( this IAuthenticationDatabaseService @this,
                                                                                      SqlServer.ISqlCallContext ctx,
                                                                                      IAuthenticationTypeSystem typeSystem,
                                                                                      LoginResult dbResult )
    {
        IUserInfo? info = dbResult.IsSuccess
                            ? typeSystem.UserInfo.FromUserAuthInfo( await @this.ReadUserAuthInfoAsync( ctx, 1, dbResult.UserId ) )
                            : null;
        return new UserLoginResult( info, dbResult.FailureCode, dbResult.FailureReason, dbResult.FailureCode == (int)KnownLoginFailureCode.UnregisteredUser );
    }
}
