using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Forms;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using MahApps.Metro;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using TrafficAnalyzer.IpV6;
using Application = System.Windows.Application;
using ThreadState = System.Threading.ThreadState;


namespace TrafficAnalyzer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        private static IPacketDevice _selectedDevice;
        private Thread _captureThread;
        private static readonly ObservableCollection<Packet> Captured = new ObservableCollection<Packet>();

        private ICommand OpenDumpFileCommand { get; set; }
        private ICommand SelectInterfaceCommand { get; set; }
        private ICommand BeginCaptureCommand { get; set; }
        private ICommand ResetCaptureCommand { get; set; }
        private ICommand SaveDumpFileCommand { get; set; }

        #region Commands
        private void InitCommands()
        {
            //Click="StartCaptureButtonClick"
            OpenDumpFileCommand = new RoutedUICommand();
            SelectInterfaceCommand = new RoutedUICommand();
            BeginCaptureCommand = new RoutedUICommand();
            ResetCaptureCommand = new RoutedUICommand();
            SaveDumpFileCommand = new RoutedUICommand();

            CommandBinding openDumpFile = new CommandBinding(OpenDumpFileCommand, OpenDumpFileCommandExecuted, OpenDumpFileCommandCanExecute);
            CommandBindings.Add(openDumpFile);

            CommandBinding selectInterface = new CommandBinding(SelectInterfaceCommand, SelectInterfaceExecuted, SelectInterfaceCanExecute);
            CommandBindings.Add(selectInterface);

            CommandBinding beginCapture = new CommandBinding(BeginCaptureCommand, BeginCaptureExecuted, BeginCaptureCanExecute);
            CommandBindings.Add(beginCapture);

            CommandBinding resetCapture = new CommandBinding(ResetCaptureCommand, ResetCaptureExecuted, ResetCaptureCanExecute);
            CommandBindings.Add(resetCapture);

            CommandBinding saveDumpFile = new CommandBinding(SaveDumpFileCommand, SaveDumpFileExecuted, SaveDumpFileCanExecute);
            CommandBindings.Add(saveDumpFile);

            OpenDumpFileButton.Command = OpenDumpFileCommand;
            StartCaptureButton.Command = BeginCaptureCommand;
            SelectInterfaceButton.Command = SelectInterfaceCommand;
            ResetCaptureButton.Command = ResetCaptureCommand;
            SaveDumpFileButton.Command = SaveDumpFileCommand;
        }

        private void SaveDumpFileCanExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = (Captured != null) && (Captured.Count > 0);
        }

        private void SaveDumpFileExecuted(object sender, ExecutedRoutedEventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog
                                                {
                                                    Title = "Save dump file",
                                                    Filter = "Dump file|*.pcap",
                                                };
            if (saveFileDialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                PacketDumpFile.Dump(saveFileDialog.FileName, DataLinkKind.Ethernet, 65536, Captured);
            }
        }

        private void ResetCaptureCanExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = (_selectedDevice != null) && 
                           (Captured != null) && (Captured.Count >0);
        }

        private void ResetCaptureExecuted(object sender, ExecutedRoutedEventArgs e)
        {
            if (Captured != null) Captured.Clear();

            if (_captureThread != null)
            {
                _captureThread.Abort();
                _captureThread = null;
            }
            
            StartCaptureButton.Content = "Start Capture";
        }

        private void BeginCaptureCanExecute(object sender, CanExecuteRoutedEventArgs canExecuteRoutedEventArgs)
        {
            canExecuteRoutedEventArgs.CanExecute = (_selectedDevice != null);
        }

        private void BeginCaptureExecuted(object sender, ExecutedRoutedEventArgs executedRoutedEventArgs)
        {
            if (_captureThread == null)
            {
                _captureThread = new Thread(DoCapture) { Name = "Capture Thread" };
            }

            if (_captureThread.ThreadState != ThreadState.Running)
            {
                _captureThread.Start();
                StartCaptureButton.Content = "Pause Capture";
            }
            else
            {
                _captureThread.Abort();
                _captureThread = null;
                StartCaptureButton.Content = "Start Capture";
            }
        }

        private void SelectInterfaceCanExecute(object sender, CanExecuteRoutedEventArgs canExecuteRoutedEventArgs)
        {
            canExecuteRoutedEventArgs.CanExecute = (_captureThread == null);
        }

        private void SelectInterfaceExecuted(object sender, ExecutedRoutedEventArgs executedRoutedEventArgs)
        {
            Effect = new BlurEffect();
            BeginStoryboard((Storyboard)Resources["blurElement"]);

            SelectInterfaceDialog selectInterfaceDialog = new SelectInterfaceDialog();
            var showDialog = selectInterfaceDialog.ShowDialog();
            if (showDialog != null && showDialog.Value)
            {
                _selectedDevice = selectInterfaceDialog.SelectedDevice;

                SelectedInterface.Inlines.Clear();
                SelectedInterface.Inlines.Add(new Run("Capture will start on "));
                SelectedInterface.Inlines.Add(new Run(_selectedDevice.Description) { FontWeight = FontWeights.Bold });
            }
            capturedPacketsListBox.DataContext = Captured;

            BeginStoryboard((Storyboard)Resources["sharpenElement"]);
            Effect = null;
        }

        private void OpenDumpFileCommandCanExecute(object sender, CanExecuteRoutedEventArgs canExecuteRoutedEventArgs)
        {
            canExecuteRoutedEventArgs.CanExecute = true;
        }

        private void OpenDumpFileCommandExecuted(object sender, ExecutedRoutedEventArgs executedRoutedEventArgs)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "Pcap dump file|*.pcap",
                Title = "Open saved pcap dump file",
                FileName = "e:\\dump.pcap"
            };
            if (openFileDialog.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;
            Captured.Clear();

            OfflinePacketDevice selectedDevice = new OfflinePacketDevice(openFileDialog.FileName);
            capturedPacketsListBox.DataContext = Captured;

            using (PacketCommunicator communicator = selectedDevice.Open(65536,
                                                                         PacketDeviceOpenAttributes.Promiscuous,
                                                                         1000))
            {
                communicator.ReceivePackets(0, p=>Captured.Add(p));
            }
        }

        #endregion

        public MainWindow()
        {
            InitializeComponent();
            ThemeManager.ChangeTheme(this, ThemeManager.DefaultAccents.First(a => a.Name == "Green"), Theme.Light);
            InitCommands();
            Closing += (s, e) =>
                                {
                                    if (_captureThread != null && _captureThread.ThreadState == ThreadState.Running)
                                    {
                                        _captureThread.Abort();
                                    }
                                };
            CapPackets.DataContext = Captured;

        }

        private void HandleOfflinePacket(Packet packet)
        {
            packetDetailsTreeView.Items.Clear();
            var ethernetDatagram = packet.Ethernet;
            
            if (ethernetDatagram == null) return;

            packetDetailsTreeView.Items.Add(Helpers.EthernetTreeViewItem(ethernetDatagram));

            switch (ethernetDatagram.EtherType)
            {
                case EthernetType.IpV4:
                    {
                        IpV4Datagram ipV4Datagram = ethernetDatagram.IpV4;
                        packetDetailsTreeView.Items.Add(Helpers.IpV4TreeViewItem(ipV4Datagram));

                        switch (ipV4Datagram.Protocol)
                        {
                            case IpV4Protocol.Tcp:
                                packetDetailsTreeView.Items.Add(Helpers.TCPTreeViewItem(ipV4Datagram.Tcp));
                                break;
                            case IpV4Protocol.Udp:
                                packetDetailsTreeView.Items.Add(Helpers.UDPTreeViewItem(ipV4Datagram.Udp));
                                break;
                        }

                    }
                    break;
                case EthernetType.IpV6:
                    {
                        byte[] buffer = new byte[ethernetDatagram.PayloadLength - ethernetDatagram.HeaderLength];
                        for (int i = ethernetDatagram.HeaderLength; i < ethernetDatagram.PayloadLength; i++)
                        {
                            buffer[i - ethernetDatagram.HeaderLength] = ethernetDatagram[i];
                        }
                        IpV6Datagram ipV6Datagram = new IpV6Datagram(buffer);
                        packetDetailsTreeView.Items.Add(Helpers.IpV6TreeViewItem(ipV6Datagram));
                    }
                    break;
                case EthernetType.Arp:
                    ArpDatagram arpDatagram = ethernetDatagram.Arp;

                    packetDetailsTreeView.Items.Add(Helpers.ARPTreeViewItem(arpDatagram));
                    
                    break;
            }
        }

        public void DoCapture()
        {
            do
            {
                PacketCommunicator packetCommunicator = _selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);
                /*
                using (BerkeleyPacketFilter filter = packetCommunicator.CreateFilter("ip and tcp"))
                {
                    // Set the filter
                    packetCommunicator.SetFilter(filter);
                }
                 */
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
// ReSharper disable FunctionNeverReturns
        }
// ReSharper restore FunctionNeverReturns

        

        private void CapturedPacketsListBoxSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            
            if (capturedPacketsListBox.SelectedItem != null)
            {
                HandleOfflinePacket((Packet)capturedPacketsListBox.SelectedItem);
            }
            
        }

    }
}
