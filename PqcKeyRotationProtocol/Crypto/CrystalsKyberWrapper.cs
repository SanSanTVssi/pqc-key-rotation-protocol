using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Security;

namespace PqcKeyRotationProtocol.Crypto;

public readonly record struct PqcKeyPair(byte[] PublicKey, byte[] PrivateKey);
public readonly record struct PqcEncapsulation(byte[] CipherText, byte[] SharedSecret);

public sealed class CrystalsKyberWrapper : IKemWrapper
{
    private readonly KyberParameters m_parameters;
    private readonly SecureRandom m_rng;

    public CrystalsKyberWrapper()
    {
        m_parameters = KyberParameters.kyber768;
        m_rng = new SecureRandom();
    }

    public PqcKeyPair GenerateKeyPair()
    {
        var gen = new KyberKeyPairGenerator();
        gen.Init(new KyberKeyGenerationParameters(m_rng, m_parameters));
        var kp = gen.GenerateKeyPair();
        var pub = (KyberPublicKeyParameters)kp.Public;
        var priv = (KyberPrivateKeyParameters)kp.Private;
        return new PqcKeyPair(pub.GetEncoded(), priv.GetEncoded());
    }

    public PqcEncapsulation Encapsulate(byte[] peerPublic)
    {
        var pub = new KyberPublicKeyParameters(m_parameters, peerPublic);
        var kem = new KyberKemGenerator(m_rng);
        var enc = kem.GenerateEncapsulated(pub);
        var ct = enc.GetEncapsulation();
        var ss = enc.GetSecret();
        return new PqcEncapsulation(ct, ss);
    }

    public byte[] Decapsulate(byte[] privateKey, byte[] ciphertext)
    {
        var priv = new KyberPrivateKeyParameters(m_parameters, privateKey);
        var kem = new KyberKemExtractor(priv);
        return kem.ExtractSecret(ciphertext);
    }

    public static bool SecretsEqual(byte[]? a, byte[]? b)
    {
        if (a == null || b == null)
        {
            return false;
        }

        if (a.Length != b.Length)
        {
            return false;
        }

        var diff = 0;
        for (var i = 0; i < a.Length; i++)
        {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}
