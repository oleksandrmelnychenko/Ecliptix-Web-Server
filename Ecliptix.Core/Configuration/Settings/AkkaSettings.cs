// File: Ecliptix.Core/Configuration/Settings/AkkaSettings.cs
using System;

namespace Ecliptix.Core.Configuration.Settings
{
    internal sealed class AkkaSettings
    {
        public RemotingSettings Remoting { get; set; } = new();
        public ClusterSettings Cluster { get; set; } = new();
        public AkkaManagementSettings AkkaManagement { get; set; } = new();
        public ClusterBootstrapSettings ClusterBootstrap { get; set; } = new();
        public KubernetesDiscoverySettings KubernetesDiscovery { get; set; } = new();

        public sealed class RemotingSettings
        {
            public string Hostname { get; set; } = "127.0.0.1";
            public int Port { get; set; } = 4053;
        }

        public sealed class ClusterSettings
        {
            public string[] Roles { get; set; } = Array.Empty<string>();
            public string[] SeedNodes { get; set; } = Array.Empty<string>();
        }

        public sealed class AkkaManagementSettings
        {
            public string HostName { get; set; } = "127.0.0.1";
            public int Port { get; set; } = 8558;
            public string BindHostName { get; set; } = "0.0.0.0";
            public int BindPort { get; set; } = 8558;
        }

        public sealed class ClusterBootstrapSettings
        {
            public string ServiceName { get; set; } = "akka-cluster-service";
            public string PortName { get; set; } = "management";
            public int RequiredContactPointsNr { get; set; } = 1;
            public bool AutoStart { get; set; } = true;
        }

        public sealed class KubernetesDiscoverySettings
        {
            public string PodLabelSelector { get; set; } = "akka-cluster=enabled";
        }
    }
}