using System.Net;
using System.Net.Sockets;
using PqcKeyRotationProtocol.Config;

namespace PqcKeyRotationProtocol.Transport;

public class UdpClientImplementation(IProvider<AppConfig> configProvider) : IUdpClient
{
    private readonly IPEndPoint m_remote 
        = (configProvider.Provide().Mode == ApplicationMode.Client 
            ? configProvider.Provide().ClientEp 
            : configProvider.Provide().ServerEp)!;
    
    private readonly UdpClient m_client = new(
        (configProvider.Provide().Mode == ApplicationMode.Client 
            ? configProvider.Provide().ServerEp 
            : configProvider.Provide().ClientEp)!
            );
    
    public IPEndPoint Remote => m_remote;

    public Task<int> SendAsync(byte[] datagram, int bytes, IPEndPoint? endPoint) 
        => m_client.SendAsync(datagram, bytes, endPoint);

    public ValueTask<UdpReceiveResult> ReceiveAsync(CancellationToken cancellationToken) 
        => m_client.ReceiveAsync(cancellationToken);
}