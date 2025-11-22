using System.Security.Cryptography;
using System.Text;
using PqcKeyRotationProtocol.Crypto;

namespace PqcKeyRotationProtocol.Handshake;

public sealed class PqcServer(IKemWrapper kem) : IHandshakeParticipant
{
    private readonly IKemWrapper m_kem = kem;
    private readonly PqcKeyPair m_keyPair = kem.GenerateKeyPair();
    private byte[]? m_sharedSecret;
    private byte[]? m_nonce;

    public byte[] SharedSecret => m_sharedSecret ?? throw new InvalidOperationException();

    public event Action<object>? Send;

    public void OnMessage(object message)
    {
        switch (message)
        {
            case ClientHello clientHello:
                m_nonce = RandomNumberGenerator.GetBytes(16);
                var sh = new ServerHello(m_nonce, m_keyPair.PublicKey);
                Send?.Invoke(sh);
                break;
            case ClientKeyShare share:
                m_sharedSecret = m_kem.Decapsulate(m_keyPair.PrivateKey, share.CipherText);
                var mac = ComputeMac(m_sharedSecret, "server finished");
                Send?.Invoke(new Finished(mac));
                break;
            case Finished fin:
                if (!VerifyMac(fin.Mac, m_sharedSecret!, "client finished"))
                {
                    throw new CryptographicException("Client MAC verification failed");
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