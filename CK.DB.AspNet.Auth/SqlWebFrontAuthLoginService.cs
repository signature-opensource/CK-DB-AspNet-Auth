using CK.AspNet.Auth;
using System;
using System.Collections.Generic;
using CK.Auth;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using CK.DB.Auth;
using System.Linq;
using CK.Core;
using System.Diagnostics;
using CK.SqlServer;
using Microsoft.Extensions.DependencyInjection;

namespace CK.DB.AspNet.Auth;


/// <summary>
/// Implements <see cref="IWebFrontAuthLoginService"/> bounds to a <see cref="IAuthenticationDatabaseService"/>.
/// This class may be specialized (and since it is a ISingletonAmbientService, its specialization will
/// be automatically selected).
/// </summary>
public class SqlWebFrontAuthLoginService : IWebFrontAuthLoginService
{
    readonly IAuthenticationDatabaseService _authPackage;
    readonly IAuthenticationTypeSystem _typeSystem;
    readonly IReadOnlyList<string> _providers;

    /// <summary>
    /// Initializes a new <see cref="SqlWebFrontAuthLoginService"/>.
    /// </summary>
    /// <param name="authPackage">The database service to use.</param>
    /// <param name="typeSystem">The authentication type system to use.</param>
    public SqlWebFrontAuthLoginService( IAuthenticationDatabaseService authPackage, IAuthenticationTypeSystem typeSystem )
    {
        Throw.CheckNotNullArgument( authPackage );
        Throw.CheckNotNullArgument( typeSystem );
        _authPackage = authPackage;
        _typeSystem = typeSystem;
        _providers = _authPackage.AllProviders.Select( p => p.ProviderName ).ToArray();
    }

    /// <summary>
    /// Gets whether the basic authentication is available.
    /// </summary>
    public virtual bool HasBasicLogin => _authPackage.BasicProvider != null;

    /// <summary>
    /// Gets the existing providers' name that have been installed in the database.
    /// </summary>
    public virtual IReadOnlyList<string> Providers => _providers;

    /// <summary>
    /// Attempts to login. If it fails, null is returned. <see cref="HasBasicLogin"/> must be true for this
    /// to be called.
    /// </summary>
    /// <param name="ctx">Current Http context.</param>
    /// <param name="monitor">The activity monitor to use.</param>
    /// <param name="userName">The user name.</param>
    /// <param name="password">The password.</param>
    /// <param name="actualLogin">
    /// Set it to false to avoid login side-effect (such as updating the LastLoginTime) on success:
    /// only checks are done.
    /// </param>
    /// <returns>The <see cref="IUserInfo"/> or null.</returns>
    public virtual async Task<UserLoginResult> BasicLoginAsync( HttpContext ctx, IActivityMonitor monitor, string userName, string password, bool actualLogin = true )
    {
        Throw.CheckState( _authPackage.BasicProvider != null );
        var c = ctx.RequestServices.GetRequiredService<ISqlCallContext>();
        Debug.Assert( c.Monitor == monitor );
        LoginResult r = await _authPackage.BasicProvider.LoginUserAsync( c, userName, password, actualLogin );
        return await _authPackage.CreateUserLoginResultFromDatabaseAsync( c, _typeSystem, r );
    }

    /// <summary>
    /// Creates a payload object for a given scheme that can be used to 
    /// call <see cref="LoginAsync"/>.
    /// </summary>
    /// <param name="ctx">Current Http context.</param>
    /// <param name="monitor">The activity monitor to use.</param>
    /// <param name="scheme">The login scheme (either the provider name to use or starts with the provider name and a dot).</param>
    /// <returns>A new, empty, provider dependent login payload.</returns>
    public virtual object CreatePayload( HttpContext ctx, IActivityMonitor monitor, string scheme )
    {
        return _authPackage.FindRequiredProvider( scheme, mustHavePayload: true ).CreatePayload();
    }

    /// <summary>
    /// Attempts to login a user using a scheme.
    /// A provider for the scheme must exist and the payload must be compatible otherwise an <see cref="ArgumentException"/>
    /// is thrown.
    /// </summary>
    /// <param name="ctx">Current Http context.</param>
    /// <param name="monitor">The activity monitor to use.</param>
    /// <param name="scheme">The scheme to use.</param>
    /// <param name="payload">The provider dependent login payload.</param>
    /// <param name="actualLogin">
    /// Set it to false to avoid login side-effect (such as updating the LastLoginTime) on success:
    /// only checks are done.
    /// </param>
    /// <returns>The login result.</returns>
    public virtual async Task<UserLoginResult> LoginAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload, bool actualLogin = true )
    {
        IGenericAuthenticationProvider p = _authPackage.FindRequiredProvider( scheme, false );
        var c = ctx.RequestServices.GetRequiredService<ISqlCallContext>();
        Debug.Assert( c.Monitor == monitor );
        LoginResult r = await p.LoginUserAsync( c, payload, actualLogin );
        return await _authPackage.CreateUserLoginResultFromDatabaseAsync( c, _typeSystem, r );
    }

    /// <summary>
    /// Refreshes a <see cref="IAuthenticationInfo"/> by reading the actual user and the impersonated user if any.
    /// </summary>
    /// <param name="ctx">The current http context.</param>
    /// <param name="monitor">The monitor to use.</param>
    /// <param name="current">The current authentication info that should be refreshed. Can be null (None authentication is returned).</param>
    /// <param name="newExpires">New expiration date (can be the same as the current's one).</param>
    /// <returns>The refreshed information. Never null but may be the None authentication info.</returns>
    public virtual async Task<IAuthenticationInfo> RefreshAuthenticationInfoAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo? current, DateTime newExpires )
    {
        if( current == null ) return _typeSystem.AuthenticationInfo.None;
        var c = ctx.RequestServices.GetRequiredService<ISqlCallContext>();
        IUserAuthInfo? dbActual = await _authPackage.ReadUserAuthInfoAsync( c, current.UnsafeActualUser.UserId, current.UnsafeActualUser.UserId );
        IUserInfo? actual = _typeSystem.UserInfo.FromUserAuthInfo( dbActual );
        IAuthenticationInfo refreshed = _typeSystem.AuthenticationInfo.Create( actual, newExpires, current.CriticalExpires, current.DeviceId );
        if( refreshed.Level != AuthLevel.None && current.IsImpersonated )
        {
            IUserAuthInfo? dbUser = await _authPackage.ReadUserAuthInfoAsync( c, current.UnsafeUser.UserId, current.UnsafeUser.UserId );
            IUserInfo user = _typeSystem.UserInfo.FromUserAuthInfo( dbUser ) ?? _typeSystem.UserInfo.Anonymous;
            refreshed = refreshed.Impersonate( user );
        }
        return refreshed;
    }

}
