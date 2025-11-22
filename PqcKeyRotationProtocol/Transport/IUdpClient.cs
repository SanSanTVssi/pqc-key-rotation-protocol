using System.Net;
using System.Net.Sockets;

namespace PqcKeyRotationProtocol.Transport;

public interface IUdpClient
{
    public IPEndPoint Remote { get; }
    Task<int> SendAsync(byte[] datagram, int bytes, IPEndPoint? endPoint);

    ValueTask<UdpReceiveResult> ReceiveAsync(CancellationToken cancellationToken);
}