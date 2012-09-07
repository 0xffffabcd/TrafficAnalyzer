using System;
using System.Windows;
using System.Windows.Controls;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using TrafficAnalyzer.IpV6;

namespace TrafficAnalyzer
{
    static class Helpers
    {

        public static ResourceDictionary GetResourceItem()
        {
            const string uriString = "/TrafficAnalyzer;component/Resources/WindowResources.xaml";

            return new ResourceDictionary { Source = new Uri(uriString, UriKind.RelativeOrAbsolute) }; 
        }
    }
}
