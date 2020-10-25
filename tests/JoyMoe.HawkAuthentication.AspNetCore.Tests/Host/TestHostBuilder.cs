using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace JoyMoe.HawkAuthentication.AspNetCore.Tests.Host
{
    public static class TestHostBuilder
    {
        public static Task<IHost> BuildAsync()
        {
            return new HostBuilder()
                .ConfigureWebHost(webBuilder =>
                {
                    webBuilder
                        .UseTestServer()
                        .ConfigureServices(services =>
                        {
                            services.AddControllers();

                            services.AddSingleton<IHawkCredentialProvider>(new MockCredentialProvider());

                            services
                                .AddAuthentication(HawkConstants.AuthenticationScheme)
                                .AddHawk();
                        })
                        .Configure(app =>
                        {
                            app.UseRouting();

                            app.UseAuthentication();
                            app.UseAuthorization();

                            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
                        });
                })
                .StartAsync();
        }
    }
}
