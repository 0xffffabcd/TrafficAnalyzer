using System.Windows.Controls;
using System.Windows.Media;
using System.Xaml;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;

namespace TrafficAnalyzer
{
    static class Helpers
    {
        public static TreeViewItem EthernetTreeViewItem(EthernetDatagram ethernetDatagram)
        {

            TreeViewItem treeViewItem = new TreeViewItem
            {
                Header =
                    string.Format("Type : {0}, Header length : {1}, Payload length : {2}", ethernetDatagram.EtherType,
                                  ethernetDatagram.HeaderLength, ethernetDatagram.PayloadLength)
            };
            TreeViewItem source = new TreeViewItem { Header = string.Format("Source : {0}", ethernetDatagram.Source) };
            TreeViewItem destination = new TreeViewItem { Header = string.Format("Destination : {0}", ethernetDatagram.Destination) };
            treeViewItem.Items.Add(source);
            treeViewItem.Items.Add(destination);
            switch (ethernetDatagram.EtherType)
            {
                case EthernetType.IpV4:
                    treeViewItem.Background = new SolidColorBrush(Colors.Aqua);
                    break;
                case EthernetType.IpV6:
                    treeViewItem.Background = new SolidColorBrush(Colors.Beige);
                    break;

            }
            treeViewItem.IsExpanded = true;
            return treeViewItem;
        }

        public static TreeViewItem IpV4TreeViewItem(IpV4Datagram ipV4Datagram)
        {

            TreeViewItem treeViewItem = new TreeViewItem
            {
                Header =
                    string.Format("Source : {0}, Destination : {1}", ipV4Datagram.Source, ipV4Datagram.Destination)
            };
            TreeViewItem version = new TreeViewItem { Header = string.Format("Version : {0}", ipV4Datagram.Version) };
            TreeViewItem ihl = new TreeViewItem { Header = string.Format("Internet Header Length : {0}", ipV4Datagram.HeaderLength) };
            TreeViewItem tos = new TreeViewItem { Header = string.Format("Type Of Service : {0}", ipV4Datagram.TypeOfService) };
            TreeViewItem totalLength = new TreeViewItem { Header = string.Format("Total Length : {0}", ipV4Datagram.TotalLength) };
            TreeViewItem identification = new TreeViewItem { Header = string.Format("Identification : {0}", ipV4Datagram.Identification) };
            TreeViewItem fragmentOffset = new TreeViewItem { Header = string.Format("Fragement Offset : {0}", ipV4Datagram.Fragmentation.Offset) };
            TreeViewItem ttl = new TreeViewItem { Header = string.Format("Time To Live : {0}", ipV4Datagram.Ttl) };
            TreeViewItem protocol = new TreeViewItem { Header = string.Format("Protocol : {0}", ipV4Datagram.Protocol) };
            TreeViewItem headerChecksum = new TreeViewItem { Header = string.Format("Header Checksum: {0}, Correct : {1}", ipV4Datagram.HeaderChecksum, ipV4Datagram.IsHeaderChecksumCorrect) };
            TreeViewItem sourceAddress = new TreeViewItem { Header = string.Format("Source Address : {0}", ipV4Datagram.Source) };
            TreeViewItem destinationAddress = new TreeViewItem { Header = string.Format("Destination : {0}", ipV4Datagram.Destination) };
            treeViewItem.Items.Add(version);
            treeViewItem.Items.Add(ihl);
            treeViewItem.Items.Add(tos);
            treeViewItem.Items.Add(totalLength);
            treeViewItem.Items.Add(identification);
            treeViewItem.Items.Add(fragmentOffset);
            treeViewItem.Items.Add(ttl);
            treeViewItem.Items.Add(protocol);
            treeViewItem.Items.Add(headerChecksum);
            treeViewItem.Items.Add(sourceAddress);
            treeViewItem.Items.Add(destinationAddress);

            switch (ipV4Datagram.Protocol)
            {
                case IpV4Protocol.Tcp:
                    treeViewItem.Background = new SolidColorBrush(Colors.BurlyWood);
                    break;
                case IpV4Protocol.Udp:
                    treeViewItem.Background = new SolidColorBrush(Colors.Coral);
                    break;

            }
            treeViewItem.IsExpanded = true;
            return treeViewItem;
        }
    }
}
