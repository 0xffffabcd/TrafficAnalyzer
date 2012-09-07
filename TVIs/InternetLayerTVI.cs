using System.Windows;
using System.Windows.Controls;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.IpV4;
using TrafficAnalyzer.IpV6;

namespace TrafficAnalyzer.TVIs
{
    static class InternetLayerTVI
    {
        #region Internet Layer

        public static TreeViewItem IpV4TreeViewItem(IpV4Datagram ipV4Datagram)
        {
            var treeViewItem = new TreeViewItem
            {

                DataContext = ipV4Datagram,
                HeaderTemplate = (Helpers.GetResourceItem()["Ipv4Item"] as DataTemplate)
            };
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Version : {0}", ipV4Datagram.Version) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Internet Header Length : {0} byte(s)", ipV4Datagram.HeaderLength) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Type Of Service : {0}", ipV4Datagram.TypeOfService) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Total Length : {0} byte(s)", ipV4Datagram.TotalLength) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Identification : {0}", ipV4Datagram.Identification) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Fragement Offset : {0}", ipV4Datagram.Fragmentation.Offset) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Time To Live : {0}", ipV4Datagram.Ttl) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Protocol : {0}", ipV4Datagram.Protocol) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Header Checksum: {0}, Correct : {1}", ipV4Datagram.HeaderChecksum, ipV4Datagram.IsHeaderChecksumCorrect) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Source Address : {0}", ipV4Datagram.Source) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Destination Address: {0}", ipV4Datagram.Destination) });

            treeViewItem.HorizontalAlignment = HorizontalAlignment.Stretch;
            treeViewItem.HorizontalContentAlignment = HorizontalAlignment.Stretch;
            return treeViewItem;
        }

        public static TreeViewItem IpV6TreeViewItem(IpV6Datagram ipV6Datagram)
        {
            var item = new TreeViewItem
            {
                DataContext = ipV6Datagram,
                HeaderTemplate = (Helpers.GetResourceItem()["Ipv6Item"] as DataTemplate)
            };
            item.Items.Add(new TreeViewItem { Header = string.Format("Traffic Class : {0}", ipV6Datagram.TrafficClass) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Flow Label : {0}", ipV6Datagram.FlowLabel) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Payload Length : {0}", ipV6Datagram.PayloadLength) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Next Header : {0}", ipV6Datagram.NextHeader) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Hop Limit : {0}", ipV6Datagram.HopLimit) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Source : {0}", ipV6Datagram.Source) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Destination : {0}", ipV6Datagram.Destination) });
            var payload = new TreeViewItem { Header = string.Format("Payload : {0}", ipV6Datagram.Payload.ToHexadecimalString()) };

            payload.MouseDoubleClick += delegate
            {
                Clipboard.SetText(ipV6Datagram.Payload.ToHexadecimalString());
            };

            item.Items.Add(payload);
            return item;
        }

        public static TreeViewItem ARPTreeViewItem(ArpDatagram arpDatagram)
        {

            var item = new TreeViewItem
            {
                DataContext = arpDatagram,
                HeaderTemplate = (Helpers.GetResourceItem()["ARPItem"] as DataTemplate)
            };
            item.Items.Add(new TreeViewItem { Header = string.Format("Hardware Length : {0}", arpDatagram.HardwareLength) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Protocole Length : {0}", arpDatagram.ProtocolLength) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Operation : {0}", arpDatagram.Operation) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Sender protocol IpV4 address : {0}", arpDatagram.SenderProtocolIpV4Address) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Target protocol IpV4 address : {0}", arpDatagram.TargetProtocolIpV4Address) });

            return item;
        }

        #endregion
    }
}
