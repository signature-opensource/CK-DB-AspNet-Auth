using CK.AspNet.Auth;
using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.SqlServer;
using CK.Testing;
using Shouldly;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NUnit.Framework;
using System;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.AspNet.Auth.Tests;

[TestFixture]
public class RefreshTests
{
    [Test]
    public async Task refreshing_with_callBackend_correctly_handles_impersonation_changes_Async()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.AddSingleton<IWebFrontAuthImpersonationService, ImpersonationForEverybodyService>();
        builder.AddApplicationIdentityServiceConfiguration();
        await using var runningServer = await builder.CreateRunningAspNetAuthenticationServerAsync( SharedEngine.Map );

        var user = runningServer.Services.GetRequiredService<UserTable>();
        var basic = runningServer.Services.GetRequiredService<IBasicAuthenticationProvider>();

        using var ctx = new SqlStandardCallContext( TestHelper.Monitor );

        int idAlbert = await SetupUserAsync( ctx, "Albert", "pass", user, basic );
        int idPaula = await SetupUserAsync( ctx, "Paula", "pass", user, basic );

        var r = await runningServer.Client.AuthenticationBasicLoginAsync( "Albert", true, password: "pass" );

        var newAlbertName = Guid.NewGuid().ToString();
        await user.UserNameSetAsync( ctx, 1, idAlbert, newAlbertName );

        r = await runningServer.Client.AuthenticationRefreshAsync( callBackend: true );
        Throw.DebugAssert( r.Info != null );
        r.Info.User.UserId.ShouldBe( idAlbert );
        r.Info.User.UserName.ShouldBe( newAlbertName );

        r = await runningServer.Client.AuthenticationImpersonateAsync( idPaula );
        Throw.DebugAssert( r != null && r.Info != null );
        r.Info.User.UserName.ShouldBe( "Paula" );
        r.Info.ActualUser.UserName.ShouldBe( newAlbertName );
        r.Info.Expires.ShouldNotBeNull();

        var rRefresh = await runningServer.Client.AuthenticationRefreshAsync();
        rRefresh.Info.ShouldNotBeNull();
        rRefresh.Info.ShouldBeEquivalentTo( r.Info, "Expires should not have the time to change here." );

        newAlbertName = Guid.NewGuid().ToString();
        var newPaulaName = Guid.NewGuid().ToString();
        await user.UserNameSetAsync( ctx, 1, idAlbert, newAlbertName );
        await user.UserNameSetAsync( ctx, 1, idPaula, newPaulaName );

        r = await runningServer.Client.AuthenticationRefreshAsync( callBackend: true );
        Throw.DebugAssert( r.Info != null );
        r.Info.User.UserName.ShouldBe( newPaulaName );
        r.Info.ActualUser.UserName.ShouldBe( newAlbertName );

        await user.UserNameSetAsync( ctx, 1, idPaula, "Paula" );
        r = await runningServer.Client.AuthenticationRefreshAsync( callBackend: true );
        Throw.DebugAssert( r.Info != null );
        r.Info.User.UserName.ShouldBe( "Paula" );
        r.Info.ActualUser.UserName.ShouldBe( newAlbertName );

        await user.UserNameSetAsync( ctx, 1, idAlbert, "Albert" );
        r = await runningServer.Client.AuthenticationImpersonateAsync( idAlbert );
        Throw.DebugAssert( r != null && r.Info != null );
        r.Info.User.UserId.ShouldBe( idAlbert );
        r.Info.User.UserName.ShouldBe( newAlbertName,
            "Impersonation in the ImpersonationForEverybodyService does not refresh the actual user." );

        r = await runningServer.Client.AuthenticationRefreshAsync( callBackend: true );
        Throw.DebugAssert( r.Info != null );
        r.Info.ActualUser.UserName.ShouldBe( "Albert" );
    }

    static async Task<int> SetupUserAsync( SqlStandardCallContext ctx, string userName, string password, UserTable user, IBasicAuthenticationProvider basic )
    {
        int idUser = await user.FindByNameAsync( ctx, userName );
        if( idUser == 0 ) idUser = await user.CreateUserAsync( ctx, 1, userName );
        await basic.CreateOrUpdatePasswordUserAsync( ctx, 1, idUser, password );
        return idUser;
    }
}
