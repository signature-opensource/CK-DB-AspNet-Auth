using CK.AspNet.Auth;
using CK.Auth;
using CK.Core;
using System.Linq;
using System.Threading.Tasks;

namespace CK.DB.AspNet.Auth.Tests;

/// <summary>
/// Client calls login with userData that contains a Zone.
/// </summary>
[ExcludedCKType]
public class NoEvilZoneForPaula : IWebFrontAuthValidateLoginService
{
    public Task ValidateLoginAsync( IActivityMonitor monitor, IUserInfo loggedInUser, IWebFrontAuthValidateLoginContext context )
    {
        if( loggedInUser.UserName == "Paula"
            && context.UserData.Any( kv => kv.Key == "zone" && kv.Value == "<&>vil" ) )
        {
            context.SetError( "Validation", "Paula must not go in the <&>vil Zone!" );
        }
        return Task.CompletedTask;
    }
}
