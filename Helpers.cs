using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace TrafficAnalyzer
{
    static class Helpers
    {
        public static TreeViewItem EthernetTreeViewItem(EthernetDatagram ethernetDatagram)
        {
            const string uriString = "/TrafficAnalyzer;component/WindowResources.xaml";
            var myresourcedictionary = new ResourceDictionary { Source = new Uri(uriString, UriKind.RelativeOrAbsolute) };

            TreeViewItem treeViewItem = new TreeViewItem
                                            {
                                                IsExpanded = true,
                                                DataContext = ethernetDatagram,
                                                HeaderTemplate = (myresourcedictionary["EtherItem"] as DataTemplate)
                                            };


            treeViewItem.Items.Add(new TreeViewItem {Header = string.Format("Source : {0}", ethernetDatagram.Source)});
            treeViewItem.Items.Add(new TreeViewItem {Header = string.Format("Destination : {0}", ethernetDatagram.Destination)});
            treeViewItem.Items.Add(new TreeViewItem {Header = string.Format("Header Length : {0}", ethernetDatagram.HeaderLength)});
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Payload Length : {0}", ethernetDatagram.PayloadLength) });
            var payload = new TreeViewItem
                              {
                                  Header = new TextBlock
                                               {
                                                   Text = string.Format("Payload : 0x{0}", ethernetDatagram.Payload.ToHexadecimalString()),
                                                   TextWrapping = TextWrapping.Wrap,
                                                   Width = 380
                                               }
                              };
            payload.MouseDoubleClick += delegate { MessageBox.Show(((TextBlock)payload.Header).Text); };
            treeViewItem.Items.Add(payload);
            
            return treeViewItem;
        }

        public static TreeViewItem IpV4TreeViewItem(IpV4Datagram ipV4Datagram)
        {
            const string uriString = "/TrafficAnalyzer;component/WindowResources.xaml";
            var myresourcedictionary = new ResourceDictionary { Source = new Uri(uriString, UriKind.RelativeOrAbsolute) };

            TreeViewItem treeViewItem = new TreeViewItem
                                            {
                                                IsExpanded = true,
                                                DataContext = ipV4Datagram,
                                                HeaderTemplate = (myresourcedictionary["Ipv4Item"] as DataTemplate)
                                            };
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Version : {0}", ipV4Datagram.Version) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Internet Header Length : {0}", ipV4Datagram.HeaderLength) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Type Of Service : {0}", ipV4Datagram.TypeOfService) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Total Length : {0}", ipV4Datagram.TotalLength) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Identification : {0}", ipV4Datagram.Identification) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Fragement Offset : {0}", ipV4Datagram.Fragmentation.Offset) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Time To Live : {0}", ipV4Datagram.Ttl) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Protocol : {0}", ipV4Datagram.Protocol) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Header Checksum: {0}, Correct : {1}", ipV4Datagram.HeaderChecksum, ipV4Datagram.IsHeaderChecksumCorrect) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Source Address : {0}", ipV4Datagram.Source) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Destination Address: {0}", ipV4Datagram.Destination) });

            switch (ipV4Datagram.Protocol)
            {
                case IpV4Protocol.Tcp:
                    treeViewItem.Background = new SolidColorBrush(Colors.BurlyWood);
                    break;
                case IpV4Protocol.Udp:
                    treeViewItem.Background = new SolidColorBrush(Colors.Coral);
                    break;

            }
            return treeViewItem;
        }

        public static TreeViewItem TCPTreeViewItem(TcpDatagram tcpDatagram)
        {
            TreeViewItem item = new TreeViewItem
                                    {
                                        Header =
                                            string.Format("TCP Packet : Source Port : {0}, Destination Port : {1}",
                                                          tcpDatagram.SourcePort, tcpDatagram.DestinationPort),
                                        IsExpanded = true
                                    };
            item.Items.Add(new TreeViewItem { Header = string.Format("Sequence Number : {0}", tcpDatagram.SequenceNumber) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Acknowledgement Number : {0}", tcpDatagram.AcknowledgmentNumber) });
            item.Items.Add(new TreeViewItem { Header = string.Format("TCP Control Bits : {0}", tcpDatagram.ControlBits) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Header Length : {0}", tcpDatagram.HeaderLength) });
            return item;
        }

        public static TreeViewItem UDPTreeViewItem(UdpDatagram udpDatagram)
        {
            TreeViewItem item = new TreeViewItem {Header = string.Format("UDP datagram from port {0} to port {1}", udpDatagram.SourcePort, udpDatagram.DestinationPort), IsExpanded = true};
            
            return item;
        }
    }
}
