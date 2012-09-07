using System.Windows;
using System.Windows.Controls;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;

namespace TrafficAnalyzer.TVIs
{
    static class LinkLayerTVI
    {
        #region Link Layer

        

        public static TreeViewItem EthernetTreeViewItem(EthernetDatagram ethernetDatagram)
        {
            var treeViewItem = new TreeViewItem
            {

                DataContext = ethernetDatagram,
                HeaderTemplate = (Helpers.GetResourceItem()["EtherItem"] as DataTemplate)
            };


            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Source : {0}", ethernetDatagram.Source) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Destination : {0}", ethernetDatagram.Destination) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Header Length : {0} byte(s)", ethernetDatagram.HeaderLength) });
            treeViewItem.Items.Add(new TreeViewItem { Header = string.Format("Payload Length : {0} byte(s)", ethernetDatagram.PayloadLength) });
            var payload = new TreeViewItem
            {
                Header = string.Format("Payload : {0}", "0x" + ethernetDatagram.Payload.ToHexadecimalString())
            };

            payload.MouseDoubleClick += delegate
            {
                Clipboard.SetText(ethernetDatagram.Payload.ToHexadecimalString());
            };
            treeViewItem.Items.Add(payload);

            return treeViewItem;
        }

        #endregion
    }
}
