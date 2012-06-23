using System;
using System.Windows;
using System.Windows.Controls;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

namespace TrafficAnalyzer
{
    static class Helpers
    {
        private static ResourceDictionary GetResourceItem()
        {
            const string uriString = "/TrafficAnalyzer;component/WindowResources.xaml";
            var myresourcedictionary = new ResourceDictionary { Source = new Uri(uriString, UriKind.RelativeOrAbsolute) };
            return myresourcedictionary;
        }

        public static TreeViewItem EthernetTreeViewItem(EthernetDatagram ethernetDatagram)
        {
            TreeViewItem treeViewItem = new TreeViewItem
                                            {
                                                
                                                DataContext = ethernetDatagram,
                                                HeaderTemplate = (GetResourceItem()["EtherItem"] as DataTemplate)
                                            };


            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Source : {0}", ethernetDatagram.Source)});
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Destination : {0}", ethernetDatagram.Destination)});
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Header Length : {0} byte(s)", ethernetDatagram.HeaderLength) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Payload Length : {0} byte(s)", ethernetDatagram.PayloadLength) });
            var payload = new TreeViewItem
                              {
                                  Header = string.Format("Payload : {0}", ethernetDatagram.Payload)
                              };

            payload.MouseDoubleClick += delegate
                                            {
                                                MessageBox.Show("0x"+ethernetDatagram.Payload.ToHexadecimalString(),
                                                                    "Payload Data", 
                                                                    MessageBoxButton.OK, 
                                                                    MessageBoxImage.Information);
                                            };
            treeViewItem.Items.Add(payload);
            
            return treeViewItem;
        }

        public static TreeViewItem IpV4TreeViewItem(IpV4Datagram ipV4Datagram)
        {
            TreeViewItem treeViewItem = new TreeViewItem
            {

                DataContext = ipV4Datagram,
                HeaderTemplate = (GetResourceItem()["Ipv4Item"] as DataTemplate)
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

        public static TreeViewItem TCPTreeViewItem(TcpDatagram tcpDatagram)
        {

            TreeViewItem item = new TreeViewItem
                                    {
                                        
                                        DataContext = tcpDatagram,
                                        HeaderTemplate = (GetResourceItem()["TCPItem"] as DataTemplate)
                                    };
            item.Items.Add(new TreeViewItem { Header = string.Format("TCP Control Bits : {0}", tcpDatagram.ControlBits) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Acknowledgement Number : {0}", tcpDatagram.AcknowledgmentNumber) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Sequence Number : {0}", tcpDatagram.SequenceNumber) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Header Length : {0} byte(s)", tcpDatagram.HeaderLength) });
            return item;
        }

        public static TreeViewItem UDPTreeViewItem(UdpDatagram udpDatagram)
        {
            TreeViewItem item = new TreeViewItem
                                    {
                                        DataContext = udpDatagram,
                                        HeaderTemplate = (GetResourceItem()["UDPItem"] as DataTemplate)
                                    };
            item.Items.Add(new TreeViewItem { Header = string.Format("Length : {0} byte(s)", udpDatagram.Length) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Total Length : {0} byte(s)", udpDatagram.TotalLength) });
            return item;
        }

        public static TreeViewItem IpV6TreeViewItem(IpV6Datagram ipV6Datagram)
        {
            TreeViewItem item = new TreeViewItem
                                {
                                    DataContext = ipV6Datagram,
                                    HeaderTemplate = (GetResourceItem()["Ipv6Item"] as DataTemplate)
                                };
            item.Items.Add(new TreeViewItem { Header = string.Format("Source : {0}", ipV6Datagram.Source) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Destination : {0}", ipV6Datagram.Destination) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Payload Length : {0}", ipV6Datagram.PayloadLength) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Next Header : {0}", ipV6Datagram.NextHeader) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Hop Limit : {0}", ipV6Datagram.HopLimit) });
            var payload = new TreeViewItem
                                {
                                    Header = "Payload (double click to see)"
                                };

            payload.MouseDoubleClick += delegate
            {
                MessageBox.Show(BitConverter.ToString(ipV6Datagram.Payload) ,
                                    "Payload Data",
                                    MessageBoxButton.OK,
                                    MessageBoxImage.Information);
            };
            item.Items.Add(payload);
            return item;
        }

        public static TreeViewItem ARPTreeViewItem(ArpDatagram arpDatagram)
        {
            
            TreeViewItem item = new TreeViewItem
            {
                DataContext = arpDatagram,
                HeaderTemplate = (GetResourceItem()["ARPItem"] as DataTemplate)
            };
            item.Items.Add(new TreeViewItem { Header = string.Format("Hardware Length : {0}", arpDatagram.HardwareLength) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Protocole Length : {0}", arpDatagram.ProtocolLength) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Operation : {0}", arpDatagram.Operation) });
            
            item.Items.Add(new TreeViewItem { Header = string.Format("Sender protocol IpV4 address : {0}", arpDatagram.SenderProtocolIpV4Address) });
            //item.Items.Add(new TreeViewItem { Header = string.Format("Sender hardware address : {0}", arpDatagram.SenderHardwareAddress) });
            //item.Items.Add(new TreeViewItem { Header = string.Format("Sender protocol address : {0}", arpDatagram.SenderProtocolAddress) });

            item.Items.Add(new TreeViewItem { Header = string.Format("Target protocol IpV4 address : {0}", arpDatagram.TargetProtocolIpV4Address) });
            //item.Items.Add(new TreeViewItem { Header = string.Format("Target hardware address : {0}", arpDatagram.TargetHardwareAddress) });
            //item.Items.Add(new TreeViewItem { Header = string.Format("Target protocol address : {0}", arpDatagram.TargetProtocolAddress) });

            return item;
        }

        public static T[] SubArray<T>(this T[] data, int index, int length)
        {
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }

    }
}
