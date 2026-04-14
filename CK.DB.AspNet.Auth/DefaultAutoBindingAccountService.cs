using System;
using System.Threading.Tasks;
using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using CK.DB.Auth;
using CK.SqlServer;
using Microsoft.Extensions.DependencyInjection;

namespace CK.DB.AspNet.Auth;

/// <summary>
/// Default implementation that will bind accounts as long as the currently logged
/// user is <see cref="AuthLevel.Critical"/> (but this can be changed).
/// </summary>
public class DefaultAutoBindingAccountService : IWebFrontAuthAutoBindingAccountService
{
    readonly IAuthenticationDatabaseService _authPackage;

    /// <summary>
    /// Initializes a new <see cref="DefaultAutoBindingAccountService"/> with <see cref="RequiresCriticalLevel"/> sets
    /// to true by default.
    /// </summary>
    /// <param name="authPackage">The authentication database service.</param>
    public DefaultAutoBindingAccountService( IAuthenticationDatabaseService authPackage )
    {
        _authPackage = authPackage;
        RequiresCriticalLevel = true;
    }

    /// <summary>
    /// Gets or sets whether the account binding requires a current <see cref="AuthLevel.Critical"/> level.
    /// Defaults to true.
    /// This may be changed explictly at any time (but this is typically configured once at startup).
    /// </summary>
    public bool RequiresCriticalLevel { get; set; }

    /// <summary>
    /// Called for each failed login when the user is currently logged in and
    /// calls <see cref="IGenericAuthenticationProvider.CreateOrUpdateUser(ISqlCallContext, int, int, object, UCLMode)"/> to bind
    /// a new provider to the user.
    /// </summary>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="context">Account binding context.</param>
    /// <returns>
    /// The login result where the <see cref="IUserInfo.Schemes"/> contains the new scheme.
    /// </returns>
    public async Task<UserLoginResult?> BindAccountAsync( IActivityMonitor monitor, IWebFrontAuthAutoBindingAccountContext context )
    {
        if( monitor == null ) throw new ArgumentNullException( nameof( monitor ) );
        if( context == null ) throw new ArgumentNullException( nameof( context ) );
        var auth = context.InitialAuthentication;
        if( auth.IsImpersonated ) throw new ArgumentException( "Invalid impersonation.", nameof( context.InitialAuthentication ) );

        if( RequiresCriticalLevel && auth.Level != AuthLevel.Critical )
        {
            return context.SetError( "User.AccountBinding.CriticalLevelRequired", "User must be logged in Critical level." );
        }
        if( auth.Level < AuthLevel.Normal )
        {
            return context.SetError( "User.AccountBinding.AtLeastNormalLevelRequired", "User must be logged at least in Normal level." );
        }
        IGenericAuthenticationProvider p = _authPackage.FindRequiredProvider( context.CallingScheme );
        var ctx = context.HttpContext.RequestServices.GetRequiredService<ISqlCallContext>();
        // Here we trigger an actual login.
        // If a bind-without-login is required once, we'll have to introduce an option or a parameter
        // to specify it.
        // In such case, CreateUserLoginResultFromDatabase must not be called but a UserLoginResult must be returned
        // that is based on the current context.InitialAuthentication: in such case, the returned scemes is NOT modified.
        UCLResult result = await p.CreateOrUpdateUserAsync( ctx, 1, auth.User.UserId, context.Payload, UCLMode.CreateOrUpdate | UCLMode.WithActualLogin );
        return await _authPackage.CreateUserLoginResultFromDatabaseAsync( ctx, context.AuthenticationTypeSystem, result.LoginResult );
    }
}
