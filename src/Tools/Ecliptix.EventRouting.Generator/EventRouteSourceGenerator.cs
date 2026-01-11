using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace Ecliptix.EventRouting.Generator;

[Generator]
public sealed class EventRouteSourceGenerator : IIncrementalGenerator
{
    private const string AttributeFullName = "Ecliptix.Core.Infrastructure.Grpc.Routing.EventRouteAttribute";

    private static readonly DiagnosticDescriptor InvalidSignature = new(
        id: "EVTROUTE001",
        title: "Invalid event route handler signature",
        messageFormat: "Method '{0}' must be static, return Task<Result<IMessage, FailureBase>> or ValueTask<Result<IMessage, FailureBase>>, and have signature (IServiceProvider, TMessage, EventMetadata, CancellationToken)",
        category: "EventRouting",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor DuplicateRoute = new(
        id: "EVTROUTE002",
        title: "Duplicate event route",
        messageFormat: "Event route for '{0}' is already defined",
        category: "EventRouting",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor InvalidMetadata = new(
        id: "EVTROUTE003",
        title: "Invalid event route metadata",
        messageFormat: "EventRoute on method '{0}' must not use Unspecified values for EventType or Context",
        category: "EventRouting",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        IncrementalValuesProvider<RouteCandidate> candidates = context.SyntaxProvider
            .ForAttributeWithMetadataName(
                AttributeFullName,
                static (node, _) => node is MethodDeclarationSyntax,
                static (ctx, _) => CreateCandidate(ctx))
            .Where(static candidate => candidate is not null)
            .Select(static (candidate, _) => candidate!);

        IncrementalValueProvider<(Compilation, ImmutableArray<RouteCandidate>)> compilationAndCandidates =
            context.CompilationProvider.Combine(candidates.Collect());

        context.RegisterSourceOutput(compilationAndCandidates, static (spc, source) =>
            GenerateResolver(source.Item1, source.Item2, spc));
    }

    private static RouteCandidate? CreateCandidate(GeneratorAttributeSyntaxContext context)
    {
        if (context.TargetSymbol is not IMethodSymbol method)
        {
            return null;
        }

        AttributeData? attribute = context.Attributes.FirstOrDefault();
        if (attribute is null)
        {
            return null;
        }

        return new RouteCandidate(method, attribute);
    }

    private static void GenerateResolver(
        Compilation compilation,
        ImmutableArray<RouteCandidate> candidates,
        SourceProductionContext context)
    {
        INamedTypeSymbol? serviceProviderSymbol = compilation.GetTypeByMetadataName("System.IServiceProvider");
        INamedTypeSymbol? eventMetadataSymbol = compilation.GetTypeByMetadataName("Ecliptix.Protobuf.Transport.Common.EventMetadata");
        INamedTypeSymbol? cancellationTokenSymbol = compilation.GetTypeByMetadataName("System.Threading.CancellationToken");
        INamedTypeSymbol? iMessageSymbol = compilation.GetTypeByMetadataName("Google.Protobuf.IMessage");
        INamedTypeSymbol? taskSymbol = compilation.GetTypeByMetadataName("System.Threading.Tasks.Task`1");
        INamedTypeSymbol? valueTaskSymbol = compilation.GetTypeByMetadataName("System.Threading.Tasks.ValueTask`1");
        INamedTypeSymbol? resultSymbol = compilation.GetTypeByMetadataName("Ecliptix.SharedKernel.Result`2");
        INamedTypeSymbol? failureBaseSymbol = compilation.GetTypeByMetadataName("Ecliptix.SharedKernel.FailureBase");

        if (serviceProviderSymbol is null
            || eventMetadataSymbol is null
            || cancellationTokenSymbol is null
            || iMessageSymbol is null
            || taskSymbol is null
            || resultSymbol is null
            || failureBaseSymbol is null)
        {
            return;
        }

        List<RouteMethodInfo> routes = new(candidates.Length);
        HashSet<long> seenEventTypes = new(); // capacity hint unavailable in netstandard2.0

        foreach (RouteCandidate candidate in candidates)
        {
            IMethodSymbol method = candidate.Method;
            if (!IsValidSignature(method, serviceProviderSymbol, eventMetadataSymbol, cancellationTokenSymbol))
            {
                Location? location = method.Locations.FirstOrDefault();
                context.ReportDiagnostic(Diagnostic.Create(InvalidSignature, location, method.Name));
                continue;
            }

            if (!IsValidReturnType(method.ReturnType, taskSymbol, valueTaskSymbol, resultSymbol, failureBaseSymbol,
                    iMessageSymbol, out bool returnsValueTask))
            {
                Location? location = method.Locations.FirstOrDefault();
                context.ReportDiagnostic(Diagnostic.Create(InvalidSignature, location, method.Name));
                continue;
            }

            ITypeSymbol messageType = method.Parameters[1].Type;
            if (!ImplementsInterface(messageType, iMessageSymbol))
            {
                Location? location = method.Locations.FirstOrDefault();
                context.ReportDiagnostic(Diagnostic.Create(InvalidSignature, location, method.Name));
                continue;
            }

            if (!TryGetRouteMetadata(candidate.Attribute, out string? eventTypeName, out string? eventTypeExpr,
                    out string? contextExpr, out bool idempotencyRequired, out long eventTypeValue, out bool hasUnspecified))
            {
                Location? location = method.Locations.FirstOrDefault();
                context.ReportDiagnostic(Diagnostic.Create(InvalidSignature, location, method.Name));
                continue;
            }

            if (hasUnspecified)
            {
                Location? location = method.Locations.FirstOrDefault();
                context.ReportDiagnostic(Diagnostic.Create(InvalidMetadata, location, method.Name));
                continue;
            }

            if (!seenEventTypes.Add(eventTypeValue))
            {
                Location? location = method.Locations.FirstOrDefault();
                context.ReportDiagnostic(Diagnostic.Create(DuplicateRoute, location, eventTypeName));
                continue;
            }

            routes.Add(new RouteMethodInfo(
                EventTypeName: eventTypeName!,
                EventTypeExpression: eventTypeExpr!,
                ContextExpression: contextExpr!,
                IdempotencyRequired: idempotencyRequired,
                MessageType: messageType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                HandlerMethod: method.ContainingType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat) + "." + method.Name,
                ReturnsValueTask: returnsValueTask));
        }

        routes.Sort((left, right) => string.CompareOrdinal(left.EventTypeExpression, right.EventTypeExpression));

        string source = RenderResolver(routes);
        context.AddSource("GeneratedEventRouteResolver.g.cs", SourceText.From(source, Encoding.UTF8));
    }

    private static bool IsValidSignature(
        IMethodSymbol method,
        INamedTypeSymbol serviceProviderSymbol,
        INamedTypeSymbol eventMetadataSymbol,
        INamedTypeSymbol cancellationTokenSymbol)
    {
        if (!method.IsStatic || method.Parameters.Length != 4)
        {
            return false;
        }

        return SymbolEqualityComparer.Default.Equals(method.Parameters[0].Type, serviceProviderSymbol)
               && SymbolEqualityComparer.Default.Equals(method.Parameters[2].Type, eventMetadataSymbol)
               && SymbolEqualityComparer.Default.Equals(method.Parameters[3].Type, cancellationTokenSymbol);
    }

    private static bool IsValidReturnType(
        ITypeSymbol returnType,
        INamedTypeSymbol taskSymbol,
        INamedTypeSymbol? valueTaskSymbol,
        INamedTypeSymbol resultSymbol,
        INamedTypeSymbol failureBaseSymbol,
        INamedTypeSymbol iMessageSymbol,
        out bool returnsValueTask)
    {
        returnsValueTask = false;
        if (returnType is not INamedTypeSymbol taskType || taskType.TypeArguments.Length != 1)
        {
            return false;
        }

        bool isTask = SymbolEqualityComparer.Default.Equals(taskType.OriginalDefinition, taskSymbol);
        bool isValueTask = valueTaskSymbol is not null
            && SymbolEqualityComparer.Default.Equals(taskType.OriginalDefinition, valueTaskSymbol);
        if (!isTask && !isValueTask)
        {
            return false;
        }

        returnsValueTask = isValueTask;
        if (taskType.TypeArguments[0] is not INamedTypeSymbol resultType
            || !SymbolEqualityComparer.Default.Equals(resultType.OriginalDefinition, resultSymbol)
            || resultType.TypeArguments.Length != 2)
        {
            return false;
        }

        if (!SymbolEqualityComparer.Default.Equals(resultType.TypeArguments[0], iMessageSymbol))
        {
            return false;
        }

        return SymbolEqualityComparer.Default.Equals(resultType.TypeArguments[1], failureBaseSymbol);
    }

    private static bool ImplementsInterface(ITypeSymbol typeSymbol, INamedTypeSymbol interfaceSymbol)
    {
        if (SymbolEqualityComparer.Default.Equals(typeSymbol, interfaceSymbol))
        {
            return true;
        }

        return typeSymbol.AllInterfaces.Any(i => SymbolEqualityComparer.Default.Equals(i, interfaceSymbol));
    }

    private static bool TryGetRouteMetadata(
        AttributeData attribute,
        out string? eventTypeName,
        out string? eventTypeExpression,
        out string? contextExpression,
        out bool idempotencyRequired,
        out long eventTypeValue,
        out bool hasUnspecified)
    {
        eventTypeName = null;
        eventTypeExpression = null;
        contextExpression = null;
        idempotencyRequired = false;
        eventTypeValue = 0;
        hasUnspecified = false;

        if (attribute.ConstructorArguments.Length < 2)
        {
            return false;
        }

        string? eventName = GetEnumMemberName(attribute.ConstructorArguments[0]);
        string? contextName = GetEnumMemberName(attribute.ConstructorArguments[1]);

        if (eventName is null || contextName is null)
        {
            return false;
        }

        if (!TryGetEnumValue(attribute.ConstructorArguments[0], out eventTypeValue))
        {
            return false;
        }

        string eventEnumType = attribute.ConstructorArguments[0].Type?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat) ?? string.Empty;
        string contextEnumType = attribute.ConstructorArguments[1].Type?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat) ?? string.Empty;

        if (eventEnumType.Length == 0 || contextEnumType.Length == 0)
        {
            return false;
        }

        eventTypeName = eventName;
        eventTypeExpression = eventEnumType + "." + eventName;
        contextExpression = contextEnumType + "." + contextName;
        hasUnspecified = string.Equals(eventName, "Unspecified", StringComparison.Ordinal)
            || string.Equals(contextName, "Unspecified", StringComparison.Ordinal);

        foreach (KeyValuePair<string, TypedConstant> namedArg in attribute.NamedArguments)
        {
            if (string.Equals(namedArg.Key, "IdempotencyRequired", StringComparison.Ordinal))
            {
                idempotencyRequired = namedArg.Value.Value is bool b && b;
                break;
            }
        }

        return true;
    }

    private static string? GetEnumMemberName(TypedConstant constant)
    {
        if (constant.Kind != TypedConstantKind.Enum || constant.Type is null || constant.Value is null)
        {
            return null;
        }

        foreach (ISymbol member in constant.Type.GetMembers())
        {
            if (member is not IFieldSymbol field || !field.HasConstantValue)
            {
                continue;
            }

            if (Equals(field.ConstantValue, constant.Value))
            {
                return field.Name;
            }
        }

        return null;
    }

    private static bool TryGetEnumValue(TypedConstant constant, out long value)
    {
        value = 0;
        if (constant.Kind != TypedConstantKind.Enum || constant.Value is null)
        {
            return false;
        }

        value = Convert.ToInt64(constant.Value, CultureInfo.InvariantCulture);
        return true;
    }

    private static string RenderResolver(IReadOnlyList<RouteMethodInfo> routes)
    {
        // Pre-size: ~500 bytes header + ~800 bytes per route (3 methods each)
        StringBuilder builder = new(500 + routes.Count * 800);

        builder.AppendLine("// <auto-generated />");
        builder.AppendLine("using System;");
        builder.AppendLine("using System.Collections.Generic;");
        builder.AppendLine("using System.Collections.Frozen;");
        builder.AppendLine("using System.Threading;");
        builder.AppendLine("using System.Threading.Tasks;");
        builder.AppendLine("using Ecliptix.Protobuf.Transport.Common;");
        builder.AppendLine("using Ecliptix.SharedKernel;");
        builder.AppendLine("using Google.Protobuf;");
        builder.AppendLine();
        builder.AppendLine("namespace Ecliptix.Core.Infrastructure.Grpc.Routing.Generated;");
        builder.AppendLine();
        builder.AppendLine("internal sealed class GeneratedEventRouteResolver : IEventRouteResolver");
        builder.AppendLine("{");
        builder.AppendLine("    private readonly FrozenDictionary<TransportEventType, EventRoute> _routes;");
        builder.AppendLine();
        builder.AppendLine("    public GeneratedEventRouteResolver(IServiceProvider services)");
        builder.AppendLine("    {");
        builder.AppendLine("        _routes = BuildRoutes(services);");
        builder.AppendLine("    }");
        builder.AppendLine();
        builder.AppendLine("    public bool TryGetRoute(TransportEventType eventType, out EventRoute route)");
        builder.AppendLine("    {");
        builder.AppendLine("        return _routes.TryGetValue(eventType, out route);");
        builder.AppendLine("    }");
        builder.AppendLine();
        builder.AppendLine("    private static FrozenDictionary<TransportEventType, EventRoute> BuildRoutes(IServiceProvider services)");
        builder.AppendLine("    {");
        builder.AppendLine("        Dictionary<TransportEventType, EventRoute> routes = new()");
        builder.AppendLine("        {");

        for (int index = 0; index < routes.Count; index++)
        {
            RouteMethodInfo route = routes[index];
            builder.Append("            [").Append(route.EventTypeExpression).AppendLine("] = new EventRoute(");
            builder.Append("                ").Append(route.ContextExpression).AppendLine(",");
            builder.Append("                Deserialize_").Append(route.EventTypeName).AppendLine(",");
            builder.Append("                Serialize_").Append(route.EventTypeName).AppendLine(",");
            builder.Append("                (value, metadata, cancellationToken) => Handle_").Append(route.EventTypeName).AppendLine("(services, value, metadata, cancellationToken),");
            builder.Append("                ").Append(route.IdempotencyRequired ? "true" : "false").Append(')');
            if (index < routes.Count - 1)
            {
                builder.Append(',');
            }
            builder.AppendLine();
        }

        builder.AppendLine("        };");
        builder.AppendLine();
        builder.AppendLine("        return routes.ToFrozenDictionary();");
        builder.AppendLine("    }");
        builder.AppendLine();

        foreach (RouteMethodInfo route in routes)
        {
            builder.Append("    private static IMessage Deserialize_").Append(route.EventTypeName).AppendLine("(ReadOnlyMemory<byte> payload)");
            builder.AppendLine("    {");
            builder.Append("        return ").Append(route.MessageType).AppendLine(".Parser.ParseFrom(payload.Span);");
            builder.AppendLine("    }");
            builder.AppendLine();

            builder.Append("    private static ReadOnlyMemory<byte> Serialize_").Append(route.EventTypeName).AppendLine("(IMessage message)");
            builder.AppendLine("    {");
            builder.AppendLine("        return message.ToByteArray();");
            builder.AppendLine("    }");
            builder.AppendLine();

            builder.Append("    private static Task<Result<IMessage, FailureBase>> Handle_").Append(route.EventTypeName).AppendLine("(IServiceProvider services, IMessage value, EventMetadata metadata, CancellationToken cancellationToken)");
            builder.AppendLine("    {");
            builder.Append("        if (value is not ").Append(route.MessageType).AppendLine(" message)");
            builder.AppendLine("        {");
            builder.AppendLine("            return Task.FromResult(Result<IMessage, FailureBase>.Err(");
            builder.Append("                MetaDataSystemFailure.ComponentNotFound(\"Payload type mismatch for ").Append(route.EventTypeName).AppendLine("\")));");
            builder.AppendLine("        }");
            builder.Append("        return ").Append(route.HandlerMethod).Append("(services, message, metadata, cancellationToken)");
            if (route.ReturnsValueTask)
            {
                builder.Append(".AsTask()");
            }
            builder.AppendLine(";");
            builder.AppendLine("    }");
            builder.AppendLine();
        }

        builder.AppendLine("}");

        return builder.ToString();
    }

    private sealed record RouteCandidate(IMethodSymbol Method, AttributeData Attribute);

    private sealed record RouteMethodInfo(
        string EventTypeName,
        string EventTypeExpression,
        string ContextExpression,
        bool IdempotencyRequired,
        string MessageType,
        string HandlerMethod,
        bool ReturnsValueTask);

}
