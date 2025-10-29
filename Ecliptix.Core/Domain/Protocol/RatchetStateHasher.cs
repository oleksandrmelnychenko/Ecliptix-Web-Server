using System.Security.Cryptography;
using Ecliptix.Protobuf.ProtocolState;
using Serilog;

namespace Ecliptix.Core.Domain.Protocol;

public static class RatchetStateHasher
{
    private const string LogTag = "[RATCHET-STATE-HASH]";

    private const string LogMessageEmptyState = "{LogTag} Empty or missing ratchet state for ConnectId: {ConnectId}";

    public static byte[] ComputeRatchetFingerprint(EcliptixSessionState? state)
    {
        if (state?.RatchetState == null)
        {
            uint connectId = state?.ConnectId ?? 0;
            Log.Warning(LogMessageEmptyState, LogTag, connectId);
            return [];
        }

        RatchetState ratchet = state.RatchetState;

        using MemoryStream ms = new();
        using BinaryWriter writer = new(ms);

        try
        {
            if (ratchet.RootKey != null && ratchet.RootKey.Length > 0)
            {
                writer.Write(ratchet.RootKey.Length);
                writer.Write(ratchet.RootKey.ToByteArray());
            }
            else
            {
                writer.Write(0);
            }


            if (ratchet.SendingStep != null)
            {
                writer.Write(ratchet.SendingStep.CurrentIndex);
                if (ratchet.SendingStep.ChainKey != null && ratchet.SendingStep.ChainKey.Length > 0)
                {
                    writer.Write(ratchet.SendingStep.ChainKey.Length);
                    writer.Write(ratchet.SendingStep.ChainKey.ToByteArray());
                }
                else
                {
                    writer.Write(0);
                }
            }
            else
            {
                writer.Write(0U);
                writer.Write(0);
            }


            if (ratchet.ReceivingStep != null)
            {
                writer.Write(ratchet.ReceivingStep.CurrentIndex);
                if (ratchet.ReceivingStep.ChainKey != null && ratchet.ReceivingStep.ChainKey.Length > 0)
                {
                    writer.Write(ratchet.ReceivingStep.ChainKey.Length);
                    writer.Write(ratchet.ReceivingStep.ChainKey.ToByteArray());
                }
                else
                {
                    writer.Write(0);
                }
            }
            else
            {
                writer.Write(0U);
                writer.Write(0);
            }


            writer.Write(ratchet.NonceCounter);

            writer.Flush();
            byte[] canonicalData = ms.ToArray();

            byte[] fingerprint = SHA256.HashData(canonicalData);

            return fingerprint;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "{LogTag} Failed to compute ratchet fingerprint for ConnectId: {ConnectId}",
                LogTag, state.ConnectId);
            return [];
        }
    }
}
