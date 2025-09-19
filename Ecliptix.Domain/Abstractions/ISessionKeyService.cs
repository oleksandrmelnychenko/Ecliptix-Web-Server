using System.Threading.Tasks;
using Ecliptix.Domain.Utilities;

namespace Ecliptix.Domain.Abstractions;

public interface ISessionKeyService
{
    Task<Result<Unit, string>> StoreSessionKeyAsync(uint connectId, byte[] sessionKey);
    Task<Result<byte[], string>> GetSessionKeyAsync(uint connectId);
    Task<Result<Unit, string>> InvalidateSessionKeyAsync(uint connectId);
    Task<Result<Unit, string>> InvalidateAllSessionKeysAsync();
    Task<bool> HasValidSessionKeyAsync(uint connectId);
}