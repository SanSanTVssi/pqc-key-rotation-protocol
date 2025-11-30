namespace PqcKeyRotationProtocol.Transport;

using PqcKeyRotationProtocol.Handshake;

public sealed class HandshakeOrchestrator
{
    private readonly IHandshakeParticipant m_participant;
    private readonly IHandshakeTransport m_transport;
    private readonly CancellationTokenSource m_cts = new();

    public HandshakeOrchestrator(IHandshakeParticipant participant, IHandshakeTransport transport)
    {
        m_participant = participant;
        m_transport = transport;

        switch (participant)
        {
            case PqcClient client:
                client.Send += async msg => await m_transport.SendAsync(msg);
                break;
            case PqcServer server:
                server.Send += async msg => await m_transport.SendAsync(msg);
                break;
        }

        _ = StartAsync();
    }

    private async Task StartAsync()
    {
        try
        {
            while (!m_cts.IsCancellationRequested)
            {
                var msg = await m_transport.ReceiveAsync(m_cts.Token);
                m_participant.OnMessage(msg);
            }
        }
        catch (OperationCanceledException)
        {
            // ignore
        }
    }

    public void Stop() => m_cts.Cancel();
}