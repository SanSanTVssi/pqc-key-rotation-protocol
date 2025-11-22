using System.Net;

namespace PqcKeyRotationProtocol.Config;

public class AppConfig
{
    public IPEndPoint? ClientEp { get; init; }
    public IPEndPoint? ServerEp { get; init; }
    public ApplicationMode Mode { get; init; }
}