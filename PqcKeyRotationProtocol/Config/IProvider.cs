namespace PqcKeyRotationProtocol.Config;

public interface IProvider<out T>
{
    T Provide();
}