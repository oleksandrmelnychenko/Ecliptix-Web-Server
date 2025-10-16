using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Ecliptix.Domain.Memberships.Instrumentation;

public static class VerificationFlowTelemetry
{
    private const string ActivitySourceName = "Ecliptix.VerificationFlow";
    private const string MeterName = "Ecliptix.VerificationFlow";

    public static readonly ActivitySource ActivitySource = new(ActivitySourceName);
    private static readonly Meter Meter = new(MeterName);

    internal static readonly UpDownCounter<long> ActiveFlows = Meter.CreateUpDownCounter<long>(
        "verification_flow_active",
        unit: "flows",
        description: "Number of active verification flows");

    internal static readonly Counter<long> OtpSent = Meter.CreateCounter<long>(
        "verification_otp_sent_total",
        unit: "otp",
        description: "Total OTP messages sent successfully");

    internal static readonly Counter<long> OtpFailed = Meter.CreateCounter<long>(
        "verification_otp_failed_total",
        unit: "otp",
        description: "Total OTP send attempts that failed");

    internal static readonly Histogram<double> OtpSendLatency = Meter.CreateHistogram<double>(
        "verification_otp_send_latency_ms",
        unit: "ms",
        description: "Latency in milliseconds for OTP send attempts");

    internal static readonly Counter<long> ChannelDrops = Meter.CreateCounter<long>(
        "verification_channel_drop_total",
        unit: "events",
        description: "Number of verification countdown updates dropped due to backpressure or cancellation");
}
