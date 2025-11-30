using System.Net;

namespace PqcKeyRotationProtocol.Config;

public class AppConfigProvider(AppConfig config) : IProvider<AppConfig>
{
    public AppConfig Provide()
    {
        return config;
    }
}