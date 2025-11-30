using PqcKeyRotationProtocol.Config;

namespace PqcKeyRotationProtocol.Di;

public static class PqcContainerFabric
{
    public static SimpleInjector.Container GetClientContainer() => new DiRegistry().Register(ApplicationMode.Client);
    public static SimpleInjector.Container GetServerContainer() => new DiRegistry().Register(ApplicationMode.Server);
}