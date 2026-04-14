using CK.AspNet.Auth;
using CK.Core;
using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;

namespace CK.DB.AspNet.Auth.Tests;

[ExcludedCKType]
public class DirectLoginAllower : IWebFrontAuthUnsafeDirectLoginAllowService
{
    public enum What
    {
        None,
        BasicOnly,
        All
    }

    public static What Allowed { get; private set; }

    public static IDisposable SetAllow( What a )
    {
        Allowed = a;
        return Util.CreateDisposableAction( () => Allowed = What.None );
    }

    public Task<bool> AllowAsync( HttpContext ctx, IActivityMonitor monitor, string scheme, object payload )
    {
        return Allowed switch { What.BasicOnly => Task.FromResult( scheme == "Basic" ), What.All => Task.FromResult( true ), _ => Task.FromResult( false ) };
    }
}
