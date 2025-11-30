using PqcKeyRotationProtocol.Config;
using PqcKeyRotationProtocol.Crypto;
using PqcKeyRotationProtocol.Handshake;
using PqcKeyRotationProtocol.Transport;
using SimpleInjector;

namespace PqcKeyRotationProtocol.Di;

public class DiRegistry
{
    public static Container? Container { get; private set; }
    private Container? m_container;

    public Container Register(AppConfig config)
    {
        if (m_container != null) return m_container;

        m_container = new();
        
        m_container.RegisterSingleton<IProvider<AppConfig>>(() => new AppConfigProvider(config));
        m_container.RegisterSingleton<PqcClient>();
        m_container.RegisterSingleton<PqcServer>();
        m_container.Register<IHandshakeParticipant>(() =>
        {
            var config = m_container.GetInstance<IProvider<AppConfig>>().Provide();

            return config.Mode switch
            {
                ApplicationMode.Client => m_container.GetInstance<PqcClient>(),
                ApplicationMode.Server => m_container.GetInstance<PqcServer>(),
                _ => throw new ArgumentOutOfRangeException(nameof(config.Mode), config.Mode, null)
            };
        }, SimpleInjector.Lifestyle.Singleton);

        m_container.RegisterSingleton<IUdpClient, UdpClientImplementation>();
        m_container.RegisterSingleton<IHandshakeTransport, UdpHandshakeTransport>();
        m_container.RegisterSingleton<IKemWrapper, CrystalsKyberWrapper>();
        m_container.RegisterSingleton<HandshakeOrchestrator>();
        
        m_container.Verify();
        Container = m_container;

        return m_container;
    }

    public void Dispose() => Container!.Dispose();
}