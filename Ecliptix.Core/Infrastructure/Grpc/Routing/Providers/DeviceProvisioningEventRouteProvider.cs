using Ecliptix.Protobuf.Transport.DeviceProvisioning;

namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Providers;

/// <summary>
/// Placeholder route provider for DeviceProvisioning events. Extend with concrete route mappings.
/// </summary>
public sealed class DeviceProvisioningEventRouteProvider : ProtobufEventRouteProvider
{
    public DeviceProvisioningEventRouteProvider(IServiceProvider services) : base(services)
    {
        Register(DeviceProvisioningEventType.DeviceProvisioningRegisterDevice.ToString(), "device_provisioning", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(DeviceProvisioningEventType.DeviceProvisioningSecureChannelEstablish.ToString(), "device_provisioning", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(DeviceProvisioningEventType.DeviceProvisioningSecureChannelRestore.ToString(), "device_provisioning", Ecliptix.Protobuf.Common.SecureEnvelope.Parser);
        Register(DeviceProvisioningEventType.DeviceProvisioningSecureChannelAuthEstablish.ToString(), "device_provisioning", Ecliptix.Protobuf.Device.AuthenticatedEstablishRequest.Parser);
    }
}
