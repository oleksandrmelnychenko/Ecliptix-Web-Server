using System.Reflection;
using Ecliptix.Core.Domain.ProtocolNative;
using Ecliptix.SharedKernel;
using Xunit;

namespace Ecliptix.SecureProtocol.Domain.Tests.ProtocolNative;

public class InteropAdaptersTests
{
    [Theory]
    [InlineData(Ecliptix.Protocol.Server.EcliptixErrorCode.ErrorReplayAttack, EcliptixProtocolFailureType.ReplayAttempt)]
    [InlineData(Ecliptix.Protocol.Server.EcliptixErrorCode.ErrorSessionExpired, EcliptixProtocolFailureType.SessionAuthenticationFailed)]
    [InlineData(Ecliptix.Protocol.Server.EcliptixErrorCode.ErrorEncryption, EcliptixProtocolFailureType.SessionAuthenticationFailed)]
    [InlineData(Ecliptix.Protocol.Server.EcliptixErrorCode.ErrorDecryption, EcliptixProtocolFailureType.SessionAuthenticationFailed)]
    [InlineData(Ecliptix.Protocol.Server.EcliptixErrorCode.ErrorInvalidInput, EcliptixProtocolFailureType.InvalidInput)]
    public void ConvertError_MapsKnownCodes(Ecliptix.Protocol.Server.EcliptixErrorCode code, EcliptixProtocolFailureType expectedType)
    {
        // use reflection to invoke the private converter to ensure mapping stays stable
        MethodInfo? method = typeof(EcliptixProtocolSystem)
            .GetMethod("ConvertError", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        Assert.NotNull(method);

        object? result = method!.Invoke(null, new object[] { code, "err" });
        Assert.IsType<EcliptixProtocolFailure>(result);

        EcliptixProtocolFailure failure = (EcliptixProtocolFailure)result!;
        Assert.Equal(expectedType, failure.FailureType);
    }
}
