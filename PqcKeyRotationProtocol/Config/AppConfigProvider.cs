using System.Net;

namespace PqcKeyRotationProtocol.Config;

public class AppConfigProvider(ApplicationMode mode) : IProvider<AppConfig>
{
    public AppConfig Provide()
    {
        return new AppConfig
        {
            ServerEp = new IPEndPoint(IPAddress.Loopback, 5000),
            ClientEp = new IPEndPoint(IPAddress.Loopback, 5001),
            Mode = mode
        };
    }
}