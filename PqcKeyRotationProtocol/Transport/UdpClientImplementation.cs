using System.Net;
using System.Net.Sockets;
using PqcKeyRotationProtocol.Config;

namespace PqcKeyRotationProtocol.Transport;

public class UdpClientImplementation(IProvider<AppConfig> configProvider) : IUdpClient
{
    private readonly UdpClient m_client = new(
        new IPEndPoint(IPAddress.Loopback, 
            configProvider.Provide().Mode == ApplicationMode.Client ? 5000 : 5001)
    );

    private readonly IPEndPoint m_remote = new(IPAddress.Loopback, configProvider.Provide().Mode == ApplicationMode.Client ? 5001 : 5000);
    public IPEndPoint Remote => m_remote;

    public Task<int> SendAsync(byte[] datagram, int bytes, IPEndPoint? endPoint) 
        => m_client.SendAsync(datagram, bytes, endPoint);

    public ValueTask<UdpReceiveResult> ReceiveAsync(CancellationToken cancellationToken) 
        => m_client.ReceiveAsync(cancellationToken);
}