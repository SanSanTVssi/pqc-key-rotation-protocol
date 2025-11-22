using System.Security.Cryptography;
using System.Text;
using PqcKeyRotationProtocol.Crypto;

namespace PqcKeyRotationProtocol.Handshake;

public sealed class PqcClient(IKemWrapper kem) : IHandshakeParticipant
{
    private readonly IKemWrapper m_kem = kem;
    private byte[]? m_sharedSecret;
    private byte[]? m_nonce;
    private byte[]? m_serverNonce;

    public byte[] SharedSecret => m_sharedSecret ?? throw new InvalidOperationException();

    public event Action<object>? Send;

    public void Start()
    {
        m_nonce = RandomNumberGenerator.GetBytes(16);
        Send?.Invoke(new ClientHello(m_nonce));
    }

    public void OnMessage(object message)
    {
        switch (message)
        {
            case ServerHello serverHello:
                m_serverNonce = serverHello.ServerNonce;
                var enc = m_kem.Encapsulate(serverHello.ServerPublicKey);
                m_sharedSecret = enc.SharedSecret;
                Send?.Invoke(new ClientKeyShare(enc.CipherText));
                var mac = ComputeMac(m_sharedSecret, "client finished");
                Send?.Invoke(new Finished(mac));
                break;
            case Finished finished:
                if (!VerifyMac(finished.Mac, m_sharedSecret!, "server finished"))
                {
                    throw new CryptographicException("Server MAC verification failed");
                }
                break;
        }
    }

    private static byte[] ComputeMac(byte[] key, string label)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(label));
    }

    private static bool VerifyMac(byte[] mac, byte[] key, string label)
    {
        var expected = ComputeMac(key, label);
        return CryptographicOperations.FixedTimeEquals(mac, expected);
    }
}