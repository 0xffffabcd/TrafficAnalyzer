using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using MahApps.Metro;
using Microsoft.Win32;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using TrafficAnalyzer.IpV6;
using Application = System.Windows.Application;


namespace TrafficAnalyzer
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow
    {
        private static IPacketDevice _selectedDevice;
        private BackgroundWorker worker = new BackgroundWorker();
        private static readonly ObservableCollection<Packet> Captured = new ObservableCollection<Packet>();

        #region Commands

        private void SaveDumpFileCanExecute(object sender, CanExecuteRoutedEventArgs e)
        {
            e.CanExecute = (Captured != null) && (Captured.Count > 0);
            e.Handled = true;
        }

        private void SaveDumpFileExecuted(object sender, ExecutedRoutedEventArgs e)
        {
            var saveFileDialog = new SaveFileDialog
                                                {
                                                    Title = "Save dump file",
                                                    Filter = "Dump file|*.pcap",
                                                };
            if (saveFileDialog.ShowDialog().Value)
            {
                PacketDumpFile.Dump(saveFileDialog.FileName, DataLinkKind.Ethernet, 65536, Captured);
            }
            e.Handled = true;
        }

        private void ResetCaptureCanExecute(object sender, CanExecuteRoutedEventArgs canExecuteRoutedEventArgs)
        {
            canExecuteRoutedEventArgs.CanExecute = (_selectedDevice != null) && 
                                                    (Captured != null) && (Captured.Count > 0);
            canExecuteRoutedEventArgs.Handled = true;
        }

        private void ResetCaptureExecuted(object sender, ExecutedRoutedEventArgs e)
        {
            worker.CancelAsync();

            if (Captured != null)
            {
                Captured.Clear();
            }
            StartCaptureButton.Content = "Start Capture";
            e.Handled = true;

        }

        private void BeginCaptureCanExecute(object sender, CanExecuteRoutedEventArgs canExecuteRoutedEventArgs)
        {
            canExecuteRoutedEventArgs.CanExecute = (_selectedDevice != null);
            canExecuteRoutedEventArgs.Handled = true;
        }

        private void BeginCaptureExecuted(object sender, ExecutedRoutedEventArgs e)
        {
            if (!worker.IsBusy)
            {
                worker.RunWorkerAsync();
                StartCaptureButton.Content = "Pause Capture";
            }
            else
            {
                worker.CancelAsync();
                StartCaptureButton.Content = "Start Capture";
            }
            e.Handled = true;

        }

        private void SelectInterfaceCanExecute(object sender, CanExecuteRoutedEventArgs canExecuteRoutedEventArgs)
        {
            canExecuteRoutedEventArgs.CanExecute = (!worker.IsBusy || !worker.CancellationPending);
            canExecuteRoutedEventArgs.Handled = true;
        }

        private void SelectInterfaceExecuted(object sender, ExecutedRoutedEventArgs e)
        {
            Effect = new BlurEffect();
            BeginStoryboard((Storyboard)Resources["blurElement"]);

            var selectInterfaceDialog = new SelectInterfaceDialog();
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
            e.Handled = true;

        }

        private void OpenDumpFileCommandCanExecute(object sender, CanExecuteRoutedEventArgs canExecuteRoutedEventArgs)
        {
            canExecuteRoutedEventArgs.CanExecute = (!worker.IsBusy || !worker.CancellationPending);
            canExecuteRoutedEventArgs.Handled = true;
        }

        private void OpenDumpFileCommandExecuted(object sender, ExecutedRoutedEventArgs e)
        {
            var openFileDialog = new OpenFileDialog
            {
                Filter = "Pcap dump file|*.pcap",
                Title = "Open saved pcap dump file",
                FileName = "e:\\dump.pcap"
            };
            if (openFileDialog.ShowDialog().Value)
            {
                Captured.Clear();

                var selectedDevice = new OfflinePacketDevice(openFileDialog.FileName);
                capturedPacketsListBox.DataContext = Captured;

                using (var communicator = selectedDevice.Open(65536,
                                                              PacketDeviceOpenAttributes.Promiscuous,
                                                              1000))
                {
                    communicator.ReceivePackets(0, p => Captured.Add(p));
                }
                e.Handled = true;
            }
        }

        #endregion

        public MainWindow()
        {
            InitializeComponent();
            Closing += (s, e) => worker.CancelAsync();

            ThemeManager.ChangeTheme(this, ThemeManager.DefaultAccents.First(a => a.Name == "Green"), Theme.Light);
            
            worker.WorkerSupportsCancellation = true ;
            worker.DoWork += WorkerOnDoWork;
            worker.RunWorkerCompleted += WorkerOnRunWorkerCompleted;

            CapPackets.DataContext = Captured;
        }

        private void WorkerOnRunWorkerCompleted(object sender, RunWorkerCompletedEventArgs runWorkerCompletedEventArgs)
        {
            if (runWorkerCompletedEventArgs.Error != null)
            {
                MessageBox.Show(runWorkerCompletedEventArgs.Error.Message);
            }
        }

        private void WorkerOnDoWork(object sender, DoWorkEventArgs doWorkEventArgs)
        {
            DoCapture();
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
                        var buffer = new byte[ethernetDatagram.PayloadLength - ethernetDatagram.HeaderLength];
                        for (int i = ethernetDatagram.HeaderLength; i < ethernetDatagram.PayloadLength; i++)
                        {
                            buffer[i - ethernetDatagram.HeaderLength] = ethernetDatagram[i];
                        }
                        var ipV6Datagram = new IpV6Datagram(buffer);
                        packetDetailsTreeView.Items.Add(Helpers.IpV6TreeViewItem(ipV6Datagram));
                    }
                    break;
                case EthernetType.Arp:
                    ArpDatagram arpDatagram = ethernetDatagram.Arp;

                    packetDetailsTreeView.Items.Add(Helpers.ARPTreeViewItem(arpDatagram));
                    
                    break;
            }
        }

        private void DoCapture()
        {
            while ((worker != null) && (worker.CancellationPending != true))
            {
                var packetCommunicator = _selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000);

                try
                {
                    Packet packet;
                    var result = packetCommunicator.ReceivePacket(out packet);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout:
                            Debug.WriteLine("{0} Capture Timeout", new[] { DateTime.Now });
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            if (Application.Current != null)
                                Application.Current.Dispatcher.Invoke(System.Windows.Threading.DispatcherPriority.Normal,
                                                                      (Action)(() => Captured.Add(packet)));
                            break;
                        case PacketCommunicatorReceiveResult.Eof:
                            Debug.WriteLine("{0} Capture Eof", new[] { DateTime.Now });
                            break;
                        default:
                            throw new Exception("Invalid Packet Result");
                    }
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("{0} Capture Error : {1}", DateTime.Now, ex.Message);
                }
            }
        }

        

        private void CapturedPacketsListBoxSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            
            if (capturedPacketsListBox.SelectedItem != null)
            {
                HandleOfflinePacket((Packet)capturedPacketsListBox.SelectedItem);
            } else
            {
                packetDetailsTreeView.Items.Clear();
            }
            
        }

    }
}
