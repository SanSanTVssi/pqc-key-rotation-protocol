namespace PqcKeyRotationProtocol.Handshake;

public readonly record struct ClientHello(byte[] ClientNonce);
public readonly record struct ServerHello(byte[] ServerNonce, byte[] ServerPublicKey);
public readonly record struct ClientKeyShare(byte[] CipherText);
public readonly record struct Finished(byte[] Mac);