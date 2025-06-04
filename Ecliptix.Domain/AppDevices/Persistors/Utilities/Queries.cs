namespace Ecliptix.Domain.AppDevices.Persistors.Utilities;

internal static class Queries
{
    public const string RegisterAppDevice = @"
            SELECT (r).unique_id, (r).status
            FROM public.register_app_device_if_not_exists(
                @app_instance_id,
                @device_id,
                @device_type
            ) AS r;
        ";
}