using CK.AspNet.Auth;
using CK.Auth;
// CK.DB.Auth brings the CK.AuthenticationInfo model (CK.Core): this legacy code uses the CK.Auth types.
using AuthLevel = CK.Auth.AuthLevel;
using UserSchemeInfo = CK.Auth.UserSchemeInfo;
using IUserInfoProvider = CK.Auth.IUserInfoProvider;
using CK.Core;
using CK.DB.Auth;
using CK.SqlServer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;

namespace CK.DB.AspNet.Auth.Tests;

[ExcludedCKType]
public class ImpersonationForEverybodyService : IWebFrontAuthImpersonationService
{
    readonly IAuthenticationTypeSystem _typeSystem;
    readonly IAuthenticationDatabaseService _db;

    public ImpersonationForEverybodyService( IAuthenticationTypeSystem typeSystem, IAuthenticationDatabaseService db )
    {
        _typeSystem = typeSystem;
        _db = db;
    }

    public async Task<IUserInfo?> ImpersonateAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo info, int userId )
    {
        IUserAuthInfo? dbUser = await _db.ReadUserAuthInfoAsync( ctx.RequestServices.GetRequiredService<ISqlCallContext>(), 1, userId );
        return _typeSystem.UserInfo.FromUserAuthInfo( dbUser );
    }

    public Task<IUserInfo?> ImpersonateAsync( HttpContext ctx, IActivityMonitor monitor, IAuthenticationInfo info, string userName )
    {
        throw new NotImplementedException( "Not tested." );
    }
}
