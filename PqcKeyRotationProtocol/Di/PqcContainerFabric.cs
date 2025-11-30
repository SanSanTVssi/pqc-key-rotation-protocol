using System.Net;
using PqcKeyRotationProtocol.Config;

namespace PqcKeyRotationProtocol.Di;

public static class PqcContainerFabric
{
    public static SimpleInjector.Container GetClientContainer(IPEndPoint clientEp, IPEndPoint serverEp) 
        => new DiRegistry().Register(new AppConfig(ApplicationMode.Client, clientEp, serverEp));
    public static SimpleInjector.Container GetServerContainer(IPEndPoint clientEp, IPEndPoint serverEp)
        => new DiRegistry().Register(new AppConfig(ApplicationMode.Server, clientEp, serverEp));
}