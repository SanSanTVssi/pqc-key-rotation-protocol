using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using PqcKeyRotationProtocol.Handshake;

namespace PqcKeyRotationProtocol.Transport;

public sealed class UdpHandshakeTransport(IUdpClient udp) : IHandshakeTransport
{
    public async Task SendAsync(object message)
    {
        var data = JsonSerializer.SerializeToUtf8Bytes(message, message.GetType());
        await udp.SendAsync(data, data.Length, udp.Remote);
    }

    public async Task<object> ReceiveAsync(CancellationToken token)
    {
        var result = await udp.ReceiveAsync(token);
        return Deserialize(result.Buffer);
    }

    private static object Deserialize(byte[] data)
    {
        using var doc = JsonDocument.Parse(data);
        var root = doc.RootElement;
        if (root.TryGetProperty("ClientNonce", out _))
        {
            return JsonSerializer.Deserialize<ClientHello>(data)!;
        }

        if (root.TryGetProperty("ServerNonce", out _))
        {
            return JsonSerializer.Deserialize<ServerHello>(data)!;
        }

        if (root.TryGetProperty("CipherText", out _))
        {
            return JsonSerializer.Deserialize<ClientKeyShare>(data)!;
        }

        if (root.TryGetProperty("Mac", out _))
        {
            return JsonSerializer.Deserialize<Finished>(data)!;
        }
        
        throw new InvalidOperationException("Unknown message type");
    }
}