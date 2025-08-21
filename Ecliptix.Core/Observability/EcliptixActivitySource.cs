using System.Diagnostics;

namespace Ecliptix.Core.Observability;

/// <summary>
/// Centralized activity source for distributed tracing
/// </summary>
public static class EcliptixActivitySource
{
    public const string SourceName = "Ecliptix.Core";
    public const string Version = "1.0.0";
    
    public static readonly ActivitySource Instance = new(SourceName, Version);
    
    /// <summary>
    /// Creates an activity for gRPC service operations
    /// </summary>
    public static Activity? StartGrpcActivity(string serviceName, string methodName, uint? connectId = null)
    {
        var activity = Instance.StartActivity($"grpc:{serviceName}.{methodName}");
        
        activity?.SetTag("service.name", serviceName);
        activity?.SetTag("rpc.method", methodName);
        activity?.SetTag("rpc.system", "grpc");
        
        if (connectId.HasValue)
        {
            activity?.SetTag("ecliptix.connect_id", connectId.Value);
        }
        
        return activity;
    }
    
    /// <summary>
    /// Creates an activity for actor operations
    /// </summary>
    public static Activity? StartActorActivity(string actorType, string operation, uint? connectId = null)
    {
        var activity = Instance.StartActivity($"actor:{actorType}.{operation}");
        
        activity?.SetTag("actor.type", actorType);
        activity?.SetTag("actor.operation", operation);
        
        if (connectId.HasValue)
        {
            activity?.SetTag("ecliptix.connect_id", connectId.Value);
        }
        
        return activity;
    }
    
    /// <summary>
    /// Creates an activity for database operations
    /// </summary>
    public static Activity? StartDatabaseActivity(string operation, string? table = null)
    {
        var activity = Instance.StartActivity($"db:{operation}");
        
        activity?.SetTag("db.system", "mssql");
        activity?.SetTag("db.operation", operation);
        
        if (!string.IsNullOrEmpty(table))
        {
            activity?.SetTag("db.table", table);
        }
        
        return activity;
    }
    
    /// <summary>
    /// Creates an activity for SMS operations
    /// </summary>
    public static Activity? StartSmsActivity(string operation, uint? connectId = null)
    {
        var activity = Instance.StartActivity($"sms:{operation}");
        
        activity?.SetTag("messaging.system", "twilio");
        activity?.SetTag("messaging.operation", operation);
        
        if (connectId.HasValue)
        {
            activity?.SetTag("ecliptix.connect_id", connectId.Value);
        }
        
        return activity;
    }
}