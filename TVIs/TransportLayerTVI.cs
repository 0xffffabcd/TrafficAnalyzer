using System.Windows;
using System.Windows.Controls;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Transport;

namespace TrafficAnalyzer.TVIs
{
    static class TransportLayerTVI
    {
        #region Tranport Layer

        public static TreeViewItem TCPTreeViewItem(TcpDatagram tcpDatagram)
        {

            var item = new TreeViewItem
            {
                DataContext = tcpDatagram,
                HeaderTemplate = (Helpers.GetResourceItem()["TCPItem"] as DataTemplate)
            };
            item.Items.Add(new TreeViewItem { Header = string.Format("TCP Control Bits : {0}", tcpDatagram.ControlBits) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Acknowledgement Number : {0}", tcpDatagram.AcknowledgmentNumber) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Sequence Number : {0}", tcpDatagram.SequenceNumber) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Header Length : {0} byte(s)", tcpDatagram.HeaderLength) });
            return item;
        }

        public static TreeViewItem UDPTreeViewItem(UdpDatagram udpDatagram)
        {
            var item = new TreeViewItem
            {
                DataContext = udpDatagram,
                HeaderTemplate = (Helpers.GetResourceItem()["UDPItem"] as DataTemplate)
            };
            item.Items.Add(new TreeViewItem { Header = string.Format("Length : {0} byte(s)", udpDatagram.Length) });
            item.Items.Add(new TreeViewItem { Header = string.Format("Total Length : {0} byte(s)", udpDatagram.TotalLength) });
            return item;
        }

        public static TreeViewItem ICMPTreeViewItem(IcmpDatagram icmpDatagram)
        {
            var item = new TreeViewItem()
            {
                DataContext = icmpDatagram,
                HeaderTemplate = (Helpers.GetResourceItem()["icmpItem"] as DataTemplate)
            };
            item.Items.Add(new TreeViewItem { Header = string.Format("Payload : {0}", icmpDatagram.Payload.ToHexadecimalString()) });
            return item;
        }

        #endregion
    }
}
