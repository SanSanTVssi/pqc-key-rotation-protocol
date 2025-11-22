namespace PqcKeyRotationProtocol.Crypto;

public interface IKemWrapper
{
    PqcKeyPair GenerateKeyPair();
    PqcEncapsulation Encapsulate(byte[] peerPublic);
    byte[] Decapsulate(byte[] privateKey, byte[] ciphertext);
}