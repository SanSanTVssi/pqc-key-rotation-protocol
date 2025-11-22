namespace PqcKeyRotationProtocol.Handshake;

public interface IHandshakeParticipant
{
    byte[] SharedSecret { get; }
    void OnMessage(object message);
}