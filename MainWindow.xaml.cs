using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using MessageBox = System.Windows.Forms.MessageBox;
using ThreadState = System.Threading.ThreadState;


namespace TrafficAnalyzer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        public static IPacketDevice SelectedDevice;
        public Thread CaptureThread;
        public static ObservableCollection<Packet> Captured = new ObservableCollection<Packet>();

        public MainWindow()
        {
            InitializeComponent();
        }

        private void GetInterfaces()
        {
            SelectInterfaceDialog selectInterfaceDialog = new SelectInterfaceDialog();
            var showDialog = selectInterfaceDialog.ShowDialog();
            if (showDialog != null && showDialog.Value)
            {
                SelectedDevice = selectInterfaceDialog.SelectedDevice;
                label1.Content = String.Format("Capture will start on {0}", SelectedDevice.Description);
            }
            capturedPacketsListBox.DataContext = Captured;
        }

        private void StartCaptureButtonClick(object sender, RoutedEventArgs e)
        {
            /*
            if (CaptureThread == null)
            {
                CaptureThread = new Thread(DoCapture) { Name = "Capture Thread" };
            }

            if (CaptureThread.ThreadState != ThreadState.Running)
            {
                CaptureThread.Start();
                startCaptureButton.Content = "Stop Capture";
            }
            else
            {
                CaptureThread.Abort();
                CaptureThread = null;
                startCaptureButton.Content = "Start Capture";
            }
            */

            OfflinePacketDevice selectedDevice = new OfflinePacketDevice("e:\\dump.pcap");
            capturedPacketsListBox.DataContext = Captured;
            // Open the capture file
            using (PacketCommunicator communicator = selectedDevice.Open(65536,
                                                    PacketDeviceOpenAttributes.Promiscuous,
                                                    1000))
            {
                // Read and dispatch packets until EOF is reached
                communicator.ReceivePackets(0, DispatcherHandler);
            }
        }

        private void DispatcherHandler(Packet packet)
        {
            Captured.Add(packet);
            var ethernetDatagram = packet.Ethernet;
            if (ethernetDatagram != null)
            {
                var t = EthernetTreeViewItem(ethernetDatagram);
                if (ethernetDatagram.EtherType == EthernetType.IpV4)
                {
                    IpV4Datagram p = ethernetDatagram.IpV4;
                    t.Items.Add(IpV4TreeViewItem(p));
                }
                treeView1.Items.Add(t);
            }
        }

        private static TreeViewItem EthernetTreeViewItem(EthernetDatagram ethernetDatagram)
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
            return treeViewItem;
        }

        private static TreeViewItem IpV4TreeViewItem(IpV4Datagram ipV4Datagram)
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
            return treeViewItem;
        }


        public void DoCapture()
        {
            do
            {
                PacketCommunicator packetCommunicator = SelectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);
                using (BerkeleyPacketFilter filter = packetCommunicator.CreateFilter("ip and tcp"))
                {
                    // Set the filter
                    packetCommunicator.SetFilter(filter);
                }
                try
                {
                    Packet packet;
                    PacketCommunicatorReceiveResult result = packetCommunicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout:
                            Debug.WriteLine(string.Format("{0} Capture Timeout", DateTime.Now));
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            if (Application.Current != null)
                                Application.Current.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal,
                                                                      (Action)(() => Captured.Add(packet)));
                            break;
                        case PacketCommunicatorReceiveResult.Eof:
                            Debug.WriteLine(string.Format("{0} Capture Eof", DateTime.Now));
                            break;
                        default:
                            throw new Exception("Invalid Packet Result");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(string.Format("{0} Capture Error : {1}",DateTime.Now,ex.Message));
                }
                
            } while (true);

        }

        private void Button1Click(object sender, RoutedEventArgs e)
        {
            GetInterfaces();
        }

        private void WindowClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            if (CaptureThread != null && CaptureThread.ThreadState == ThreadState.Running)
            {
                CaptureThread.Abort();
            }
        }

        private void CapturedPacketsListBoxSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            /*
            if (capturedPacketsListBox.SelectedItem != null)
            {
                EthernetVisualizer.Datagram = ((Packet)capturedPacketsListBox.SelectedItem).Ethernet;
            }
             **/
        }
    }
}
