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
        messageFormat: "Method '{0}' has invalid signature for delivery kind {1}. Expected: {2}.",
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
                static (attributeSyntaxContext, _) => CreateCandidate(attributeSyntaxContext))
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
        INamedTypeSymbol? taskNonGenericSymbol = compilation.GetTypeByMetadataName("System.Threading.Tasks.Task");
        INamedTypeSymbol? valueTaskSymbol = compilation.GetTypeByMetadataName("System.Threading.Tasks.ValueTask`1");
        INamedTypeSymbol? resultSymbol = compilation.GetTypeByMetadataName("Ecliptix.SharedKernel.Result`2");
        INamedTypeSymbol? failureBaseSymbol = compilation.GetTypeByMetadataName("Ecliptix.SharedKernel.FailureBase");
        INamedTypeSymbol? serverStreamWriterSymbol = compilation.GetTypeByMetadataName("Grpc.Core.IServerStreamWriter`1");
        INamedTypeSymbol? asyncEnumerableSymbol = compilation.GetTypeByMetadataName("System.Collections.Generic.IAsyncEnumerable`1");

        if (serviceProviderSymbol is null
            || eventMetadataSymbol is null
            || cancellationTokenSymbol is null
            || iMessageSymbol is null
            || taskSymbol is null
            || taskNonGenericSymbol is null
            || resultSymbol is null
            || failureBaseSymbol is null
            || serverStreamWriterSymbol is null
            || asyncEnumerableSymbol is null)
        {
            return;
        }

        SymbolContext symbols = new(
            serviceProviderSymbol,
            eventMetadataSymbol,
            cancellationTokenSymbol,
            iMessageSymbol,
            taskSymbol,
            taskNonGenericSymbol,
            valueTaskSymbol,
            resultSymbol,
            failureBaseSymbol,
            serverStreamWriterSymbol,
            asyncEnumerableSymbol);

        List<RouteMethodInfo> routes = new(candidates.Length);
        HashSet<long> seenEventTypes = new();

        foreach (RouteCandidate candidate in candidates)
        {
            IMethodSymbol method = candidate.Method;

            if (!TryGetRouteMetadata(candidate.Attribute, out string? eventTypeName, out string? eventTypeExpr,
                    out string? contextExpr, out string? deliveryKindExpr, out DeliveryKindType deliveryKind,
                    out bool idempotencyRequired, out bool requiresDeviceId,
                    out bool requiresApplicationInstanceId, out long eventTypeValue, out bool hasUnspecified))
            {
                Location? location = method.Locations.FirstOrDefault();
                context.ReportDiagnostic(Diagnostic.Create(InvalidSignature, location, method.Name, "Unknown", "Valid attribute"));
                continue;
            }

            if (hasUnspecified)
            {
                Location? location = method.Locations.FirstOrDefault();
                context.ReportDiagnostic(Diagnostic.Create(InvalidMetadata, location, method.Name));
                continue;
            }

            if (!ValidateHandlerSignature(method, deliveryKind, symbols, out string? messageType, out bool returnsValueTask, out string expectedSignature))
            {
                Location? location = method.Locations.FirstOrDefault();
                context.ReportDiagnostic(Diagnostic.Create(InvalidSignature, location, method.Name, deliveryKind.ToString(), expectedSignature));
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
                DeliveryKindExpression: deliveryKindExpr!,
                DeliveryKind: deliveryKind,
                IdempotencyRequired: idempotencyRequired,
                RequiresDeviceId: requiresDeviceId,
                RequiresApplicationInstanceId: requiresApplicationInstanceId,
                MessageType: messageType!,
                HandlerMethod: method.ContainingType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat) + "." + method.Name,
                ReturnsValueTask: returnsValueTask));
        }

        routes.Sort((left, right) => string.CompareOrdinal(left.EventTypeExpression, right.EventTypeExpression));

        string source = RenderResolver(routes);
        context.AddSource("GeneratedEventRouteResolver.g.cs", SourceText.From(source, Encoding.UTF8));
    }

    private static bool ValidateHandlerSignature(
        IMethodSymbol method,
        DeliveryKindType deliveryKind,
        SymbolContext symbols,
        out string? messageType,
        out bool returnsValueTask,
        out string expectedSignature)
    {
        messageType = null;
        returnsValueTask = false;

        expectedSignature = deliveryKind switch
        {
            DeliveryKindType.Unary => "(IServiceProvider, TMessage, EventMetadata, CancellationToken) -> Task<Result<IMessage, FailureBase>>",
            DeliveryKindType.ServerStream => "(IServiceProvider, TMessage, EventMetadata, IServerStreamWriter<EventEnvelope>, CancellationToken) -> Task",
            DeliveryKindType.ClientStream => "(IServiceProvider, IAsyncEnumerable<TMessage>, EventMetadata, CancellationToken) -> Task<Result<IMessage, FailureBase>>",
            DeliveryKindType.BidiStream => "(IServiceProvider, IAsyncEnumerable<TMessage>, EventMetadata, IServerStreamWriter<EventEnvelope>, CancellationToken) -> Task",
            _ => "Unknown"
        };

        if (!method.IsStatic)
        {
            return false;
        }

        return deliveryKind switch
        {
            DeliveryKindType.Unary => ValidateUnarySignature(method, symbols, out messageType, out returnsValueTask),
            DeliveryKindType.ServerStream => ValidateServerStreamSignature(method, symbols, out messageType),
            DeliveryKindType.ClientStream => ValidateClientStreamSignature(method, symbols, out messageType, out returnsValueTask),
            DeliveryKindType.BidiStream => ValidateBidiStreamSignature(method, symbols, out messageType),
            _ => false
        };
    }

    private static bool ValidateUnarySignature(
        IMethodSymbol method,
        SymbolContext symbols,
        out string? messageType,
        out bool returnsValueTask)
    {
        messageType = null;
        returnsValueTask = false;

        if (method.Parameters.Length != 4)
        {
            return false;
        }

        if (!SymbolEqualityComparer.Default.Equals(method.Parameters[0].Type, symbols.ServiceProvider)
            || !SymbolEqualityComparer.Default.Equals(method.Parameters[2].Type, symbols.EventMetadata)
            || !SymbolEqualityComparer.Default.Equals(method.Parameters[3].Type, symbols.CancellationToken))
        {
            return false;
        }

        ITypeSymbol param1Type = method.Parameters[1].Type;
        if (!ImplementsInterface(param1Type, symbols.IMessage))
        {
            return false;
        }

        if (!IsResultReturnType(method.ReturnType, symbols, out returnsValueTask))
        {
            return false;
        }

        messageType = param1Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        return true;
    }

    private static bool ValidateServerStreamSignature(
        IMethodSymbol method,
        SymbolContext symbols,
        out string? messageType)
    {
        messageType = null;

        if (method.Parameters.Length != 5)
        {
            return false;
        }

        if (!SymbolEqualityComparer.Default.Equals(method.Parameters[0].Type, symbols.ServiceProvider)
            || !SymbolEqualityComparer.Default.Equals(method.Parameters[2].Type, symbols.EventMetadata)
            || !SymbolEqualityComparer.Default.Equals(method.Parameters[4].Type, symbols.CancellationToken))
        {
            return false;
        }

        ITypeSymbol param1Type = method.Parameters[1].Type;
        if (!ImplementsInterface(param1Type, symbols.IMessage))
        {
            return false;
        }

        if (!IsServerStreamWriter(method.Parameters[3].Type, symbols))
        {
            return false;
        }

        if (!SymbolEqualityComparer.Default.Equals(method.ReturnType, symbols.TaskNonGeneric))
        {
            return false;
        }

        messageType = param1Type.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        return true;
    }

    private static bool ValidateClientStreamSignature(
        IMethodSymbol method,
        SymbolContext symbols,
        out string? messageType,
        out bool returnsValueTask)
    {
        messageType = null;
        returnsValueTask = false;

        if (method.Parameters.Length != 4)
        {
            return false;
        }

        if (!SymbolEqualityComparer.Default.Equals(method.Parameters[0].Type, symbols.ServiceProvider)
            || !SymbolEqualityComparer.Default.Equals(method.Parameters[2].Type, symbols.EventMetadata)
            || !SymbolEqualityComparer.Default.Equals(method.Parameters[3].Type, symbols.CancellationToken))
        {
            return false;
        }

        if (!TryGetAsyncEnumerableElementType(method.Parameters[1].Type, symbols, out ITypeSymbol? elementType))
        {
            return false;
        }

        if (!ImplementsInterface(elementType!, symbols.IMessage))
        {
            return false;
        }

        if (!IsResultReturnType(method.ReturnType, symbols, out returnsValueTask))
        {
            return false;
        }

        messageType = elementType!.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        return true;
    }

    private static bool ValidateBidiStreamSignature(
        IMethodSymbol method,
        SymbolContext symbols,
        out string? messageType)
    {
        messageType = null;

        if (method.Parameters.Length != 5)
        {
            return false;
        }

        if (!SymbolEqualityComparer.Default.Equals(method.Parameters[0].Type, symbols.ServiceProvider)
            || !SymbolEqualityComparer.Default.Equals(method.Parameters[2].Type, symbols.EventMetadata)
            || !SymbolEqualityComparer.Default.Equals(method.Parameters[4].Type, symbols.CancellationToken))
        {
            return false;
        }

        if (!TryGetAsyncEnumerableElementType(method.Parameters[1].Type, symbols, out ITypeSymbol? elementType))
        {
            return false;
        }

        if (!ImplementsInterface(elementType!, symbols.IMessage))
        {
            return false;
        }

        if (!IsServerStreamWriter(method.Parameters[3].Type, symbols))
        {
            return false;
        }

        if (!SymbolEqualityComparer.Default.Equals(method.ReturnType, symbols.TaskNonGeneric))
        {
            return false;
        }

        messageType = elementType!.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
        return true;
    }

    private static bool IsResultReturnType(ITypeSymbol returnType, SymbolContext symbols, out bool returnsValueTask)
    {
        returnsValueTask = false;

        if (returnType is not INamedTypeSymbol taskType || taskType.TypeArguments.Length != 1)
        {
            return false;
        }

        bool isTask = SymbolEqualityComparer.Default.Equals(taskType.OriginalDefinition, symbols.Task);
        bool isValueTask = symbols.ValueTask is not null
            && SymbolEqualityComparer.Default.Equals(taskType.OriginalDefinition, symbols.ValueTask);

        if (!isTask && !isValueTask)
        {
            return false;
        }

        returnsValueTask = isValueTask;

        if (taskType.TypeArguments[0] is not INamedTypeSymbol resultType
            || !SymbolEqualityComparer.Default.Equals(resultType.OriginalDefinition, symbols.Result)
            || resultType.TypeArguments.Length != 2)
        {
            return false;
        }

        return SymbolEqualityComparer.Default.Equals(resultType.TypeArguments[0], symbols.IMessage)
            && SymbolEqualityComparer.Default.Equals(resultType.TypeArguments[1], symbols.FailureBase);
    }

    private static bool IsServerStreamWriter(ITypeSymbol type, SymbolContext symbols)
    {
        if (type is not INamedTypeSymbol namedType || namedType.TypeArguments.Length != 1)
        {
            return false;
        }

        return SymbolEqualityComparer.Default.Equals(namedType.OriginalDefinition, symbols.ServerStreamWriter);
    }

    private static bool TryGetAsyncEnumerableElementType(ITypeSymbol type, SymbolContext symbols, out ITypeSymbol? elementType)
    {
        elementType = null;

        if (type is not INamedTypeSymbol namedType || namedType.TypeArguments.Length != 1)
        {
            return false;
        }

        if (!SymbolEqualityComparer.Default.Equals(namedType.OriginalDefinition, symbols.AsyncEnumerable))
        {
            return false;
        }

        elementType = namedType.TypeArguments[0];
        return true;
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
        out string? deliveryKindExpression,
        out DeliveryKindType deliveryKind,
        out bool idempotencyRequired,
        out bool requiresDeviceId,
        out bool requiresApplicationInstanceId,
        out long eventTypeValue,
        out bool hasUnspecified)
    {
        eventTypeName = null;
        eventTypeExpression = null;
        contextExpression = null;
        deliveryKindExpression = null;
        deliveryKind = DeliveryKindType.Unary;
        idempotencyRequired = false;
        requiresDeviceId = false;
        requiresApplicationInstanceId = false;
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

        if (attribute.ConstructorArguments.Length >= 3)
        {
            string? deliveryKindName = GetEnumMemberName(attribute.ConstructorArguments[2]);
            string deliveryKindEnumType = attribute.ConstructorArguments[2].Type?.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat) ?? string.Empty;

            if (deliveryKindName is not null && deliveryKindEnumType.Length > 0)
            {
                deliveryKindExpression = deliveryKindEnumType + "." + deliveryKindName;
                deliveryKind = deliveryKindName switch
                {
                    "Unary" => DeliveryKindType.Unary,
                    "ServerStream" => DeliveryKindType.ServerStream,
                    "ClientStream" => DeliveryKindType.ClientStream,
                    "BidiStream" => DeliveryKindType.BidiStream,
                    _ => DeliveryKindType.Unary
                };
            }
        }

        deliveryKindExpression ??= "global::Ecliptix.Protobuf.Transport.Common.DeliveryKind.Unary";

        foreach (KeyValuePair<string, TypedConstant> namedArg in attribute.NamedArguments)
        {
            if (string.Equals(namedArg.Key, "IdempotencyRequired", StringComparison.Ordinal))
            {
                idempotencyRequired = namedArg.Value.Value is bool b && b;
            }
            else if (string.Equals(namedArg.Key, "RequiresDeviceId", StringComparison.Ordinal))
            {
                requiresDeviceId = namedArg.Value.Value is bool b && b;
            }
            else if (string.Equals(namedArg.Key, "RequiresApplicationInstanceId", StringComparison.Ordinal))
            {
                requiresApplicationInstanceId = namedArg.Value.Value is bool b && b;
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
        StringBuilder builder = new(700 + routes.Count * 1000);

        builder.AppendLine("// <auto-generated />");
        builder.AppendLine("using System;");
        builder.AppendLine("using System.Collections.Generic;");
        builder.AppendLine("using System.Collections.Frozen;");
        builder.AppendLine("using System.Threading;");
        builder.AppendLine("using System.Threading.Tasks;");
        builder.AppendLine("using Ecliptix.Protobuf.Transport.Common;");
        builder.AppendLine("using Ecliptix.SharedKernel;");
        builder.AppendLine("using Google.Protobuf;");
        builder.AppendLine("using Grpc.Core;");
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
            builder.Append("                ").Append(route.DeliveryKindExpression).AppendLine(",");
            builder.Append("                Deserialize_").Append(route.EventTypeName).AppendLine(",");
            builder.Append("                Serialize_").Append(route.EventTypeName).AppendLine(",");

            if (route.DeliveryKind == DeliveryKindType.Unary)
            {
                builder.Append("                (message, metadata, cancellationToken) => HandleUnary_").Append(route.EventTypeName).AppendLine("(services, message, metadata, cancellationToken),");
            }
            else
            {
                builder.AppendLine("                null,");
            }

            if (route.DeliveryKind == DeliveryKindType.ServerStream)
            {
                builder.Append("                (message, metadata, stream, cancellationToken) => HandleServerStream_").Append(route.EventTypeName).AppendLine("(services, message, metadata, stream, cancellationToken),");
            }
            else
            {
                builder.AppendLine("                null,");
            }

            if (route.DeliveryKind == DeliveryKindType.ClientStream)
            {
                builder.Append("                (messages, metadata, cancellationToken) => HandleClientStream_").Append(route.EventTypeName).AppendLine("(services, messages, metadata, cancellationToken),");
            }
            else
            {
                builder.AppendLine("                null,");
            }

            if (route.DeliveryKind == DeliveryKindType.BidiStream)
            {
                builder.Append("                (messages, metadata, stream, cancellationToken) => HandleBidiStream_").Append(route.EventTypeName).AppendLine("(services, messages, metadata, stream, cancellationToken),");
            }
            else
            {
                builder.AppendLine("                null,");
            }

            builder.Append("                ").Append(route.IdempotencyRequired ? "true" : "false").AppendLine(",");
            builder.Append("                ").Append(route.RequiresDeviceId ? "true" : "false").AppendLine(",");
            builder.Append("                ").Append(route.RequiresApplicationInstanceId ? "true" : "false").Append(')');
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

            switch (route.DeliveryKind)
            {
                case DeliveryKindType.Unary:
                    RenderUnaryHandler(builder, route);
                    break;
                case DeliveryKindType.ServerStream:
                    RenderServerStreamHandler(builder, route);
                    break;
                case DeliveryKindType.ClientStream:
                    RenderClientStreamHandler(builder, route);
                    break;
                case DeliveryKindType.BidiStream:
                    RenderBidiStreamHandler(builder, route);
                    break;
            }
        }

        builder.AppendLine("}");

        return builder.ToString();
    }

    private static void RenderUnaryHandler(StringBuilder builder, RouteMethodInfo route)
    {
        builder.Append("    private static Task<Result<IMessage, FailureBase>> HandleUnary_").Append(route.EventTypeName).AppendLine("(IServiceProvider services, IMessage value, EventMetadata metadata, CancellationToken cancellationToken)");
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

    private static void RenderServerStreamHandler(StringBuilder builder, RouteMethodInfo route)
    {
        builder.Append("    private static Task HandleServerStream_").Append(route.EventTypeName).AppendLine("(IServiceProvider services, IMessage value, EventMetadata metadata, IServerStreamWriter<EventEnvelope> responseStream, CancellationToken cancellationToken)");
        builder.AppendLine("    {");
        builder.Append("        if (value is not ").Append(route.MessageType).AppendLine(" message)");
        builder.AppendLine("        {");
        builder.AppendLine("            return Task.CompletedTask;");
        builder.AppendLine("        }");
        builder.Append("        return ").Append(route.HandlerMethod).AppendLine("(services, message, metadata, responseStream, cancellationToken);");
        builder.AppendLine("    }");
        builder.AppendLine();
    }

    private static void RenderClientStreamHandler(StringBuilder builder, RouteMethodInfo route)
    {
        builder.Append("    private static async Task<Result<IMessage, FailureBase>> HandleClientStream_").Append(route.EventTypeName).AppendLine("(IServiceProvider services, IAsyncEnumerable<IMessage> values, EventMetadata metadata, CancellationToken cancellationToken)");
        builder.AppendLine("    {");
        builder.Append("        async IAsyncEnumerable<").Append(route.MessageType).AppendLine("> CastStream()");
        builder.AppendLine("        {");
        builder.AppendLine("            await foreach (var value in values.WithCancellation(cancellationToken))");
        builder.AppendLine("            {");
        builder.Append("                if (value is ").Append(route.MessageType).AppendLine(" typed)");
        builder.AppendLine("                {");
        builder.AppendLine("                    yield return typed;");
        builder.AppendLine("                }");
        builder.AppendLine("            }");
        builder.AppendLine("        }");
        builder.Append("        return await ").Append(route.HandlerMethod).Append("(services, CastStream(), metadata, cancellationToken)");
        if (route.ReturnsValueTask)
        {
            builder.Append(".AsTask()");
        }
        builder.AppendLine(";");
        builder.AppendLine("    }");
        builder.AppendLine();
    }

    private static void RenderBidiStreamHandler(StringBuilder builder, RouteMethodInfo route)
    {
        builder.Append("    private static Task HandleBidiStream_").Append(route.EventTypeName).AppendLine("(IServiceProvider services, IAsyncEnumerable<IMessage> values, EventMetadata metadata, IServerStreamWriter<EventEnvelope> responseStream, CancellationToken cancellationToken)");
        builder.AppendLine("    {");
        builder.Append("        async IAsyncEnumerable<").Append(route.MessageType).AppendLine("> CastStream()");
        builder.AppendLine("        {");
        builder.AppendLine("            await foreach (var value in values.WithCancellation(cancellationToken))");
        builder.AppendLine("            {");
        builder.Append("                if (value is ").Append(route.MessageType).AppendLine(" typed)");
        builder.AppendLine("                {");
        builder.AppendLine("                    yield return typed;");
        builder.AppendLine("                }");
        builder.AppendLine("            }");
        builder.AppendLine("        }");
        builder.Append("        return ").Append(route.HandlerMethod).AppendLine("(services, CastStream(), metadata, responseStream, cancellationToken);");
        builder.AppendLine("    }");
        builder.AppendLine();
    }

    private sealed record RouteCandidate(IMethodSymbol Method, AttributeData Attribute);

    private sealed record RouteMethodInfo(
        string EventTypeName,
        string EventTypeExpression,
        string ContextExpression,
        string DeliveryKindExpression,
        DeliveryKindType DeliveryKind,
        bool IdempotencyRequired,
        bool RequiresDeviceId,
        bool RequiresApplicationInstanceId,
        string MessageType,
        string HandlerMethod,
        bool ReturnsValueTask);

    private sealed record SymbolContext(
        INamedTypeSymbol ServiceProvider,
        INamedTypeSymbol EventMetadata,
        INamedTypeSymbol CancellationToken,
        INamedTypeSymbol IMessage,
        INamedTypeSymbol Task,
        INamedTypeSymbol TaskNonGeneric,
        INamedTypeSymbol? ValueTask,
        INamedTypeSymbol Result,
        INamedTypeSymbol FailureBase,
        INamedTypeSymbol ServerStreamWriter,
        INamedTypeSymbol AsyncEnumerable);

    private enum DeliveryKindType
    {
        Unary,
        ServerStream,
        ClientStream,
        BidiStream
    }
}
