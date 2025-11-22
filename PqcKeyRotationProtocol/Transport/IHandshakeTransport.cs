namespace PqcKeyRotationProtocol.Transport;

public interface IHandshakeTransport
{
    Task SendAsync(object message);
    Task<object> ReceiveAsync(CancellationToken token);
}