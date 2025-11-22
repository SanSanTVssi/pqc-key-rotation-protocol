using PqcKeyRotationProtocol.Config;
using PqcKeyRotationProtocol.Crypto;
using PqcKeyRotationProtocol.Handshake;
using PqcKeyRotationProtocol.Transport;
using SimpleInjector;

namespace PqcKeyRotationProtocol.Di;

public class DiRegistry
{
    public static Container? Container { get; private set; }
    private readonly Container? m_container = new();
    private bool m_initialized;

    public Container? Register(ApplicationMode mode)
    {
        if (m_initialized) return m_container;

        m_container.RegisterSingleton<IProvider<AppConfig>>(() => new AppConfigProvider(mode));
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
        
        m_initialized = true;
        Container = m_container;

        return m_container;
    }
}