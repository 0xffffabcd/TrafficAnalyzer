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
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using Application = System.Windows.Application;
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

        private ICommand OpenDumpFileCommand { get; set; }
        private ICommand SelectInterfaceCommand { get; set; }
        private ICommand BeginCaptureCommand { get; set; }

        #region Commands
        private void InitCommands()
        {
            //Click="StartCaptureButtonClick"
            OpenDumpFileCommand = new RoutedUICommand();
            SelectInterfaceCommand = new RoutedUICommand();
            BeginCaptureCommand = new RoutedUICommand();

            CommandBinding openDumpFile = new CommandBinding(OpenDumpFileCommand, OpenDumpFileCommandExecuted, OpenDumpFileCommandCanExecute);
            CommandBindings.Add(openDumpFile);

            CommandBinding selectInterface = new CommandBinding(SelectInterfaceCommand, SelectInterfaceExecuted, SelectInterfaceCanExecute);
            CommandBindings.Add(selectInterface);

            CommandBinding beginCapture = new CommandBinding(BeginCaptureCommand, BeginCaptureExecuted, BeginCaptureCanExecute);
            CommandBindings.Add(beginCapture);

            OpenDumpFileButton.Command = OpenDumpFileCommand;
            StartCaptureButton.Command = BeginCaptureCommand;
            SelectInterfaceButton.Command = SelectInterfaceCommand;
        }

        private void BeginCaptureCanExecute(object sender, CanExecuteRoutedEventArgs canExecuteRoutedEventArgs)
        {
            canExecuteRoutedEventArgs.CanExecute = (SelectedDevice != null);
        }

        private void BeginCaptureExecuted(object sender, ExecutedRoutedEventArgs executedRoutedEventArgs)
        {
            if (CaptureThread == null)
            {
                CaptureThread = new Thread(DoCapture) { Name = "Capture Thread" };
            }

            if (CaptureThread.ThreadState != ThreadState.Running)
            {
                CaptureThread.Start();
                StartCaptureButton.Content = "Stop Capture";
            }
            else
            {
                CaptureThread.Abort();
                CaptureThread = null;
                StartCaptureButton.Content = "Start Capture";
            }
        }

        private void SelectInterfaceCanExecute(object sender, CanExecuteRoutedEventArgs canExecuteRoutedEventArgs)
        {
            canExecuteRoutedEventArgs.CanExecute = (CaptureThread == null);
        }

        private void SelectInterfaceExecuted(object sender, ExecutedRoutedEventArgs executedRoutedEventArgs)
        {
            Effect = new BlurEffect();
            BeginStoryboard((Storyboard)Resources["blurElement"]);

            SelectInterfaceDialog selectInterfaceDialog = new SelectInterfaceDialog();
            var showDialog = selectInterfaceDialog.ShowDialog();
            if (showDialog != null && showDialog.Value)
            {
                SelectedDevice = selectInterfaceDialog.SelectedDevice;
                textBlock1.Inlines.Clear();
                textBlock1.Inlines.Add(new Run("Capture will start on "));
                textBlock1.Inlines.Add(new Run(SelectedDevice.Description) { FontWeight = FontWeights.Bold });
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
                                    if (CaptureThread != null && CaptureThread.ThreadState == ThreadState.Running)
                                    {
                                        CaptureThread.Abort();
                                    }
                                };
            label1.DataContext = Captured;
        }

        private void HandleOfflinePacket(Packet packet)
        {
            treeView1.Items.Clear();
            var ethernetDatagram = packet.Ethernet;
            if (ethernetDatagram != null)
            {
                var t = Helpers.EthernetTreeViewItem(ethernetDatagram);
                if (ethernetDatagram.EtherType == EthernetType.IpV4)
                {
                    IpV4Datagram p = ethernetDatagram.IpV4;
                    t.Items.Add(Helpers.IpV4TreeViewItem(p));
                }
                treeView1.Items.Add(t);
            }
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

        

        private void CapturedPacketsListBoxSelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            
            if (capturedPacketsListBox.SelectedItem != null)
            {
                HandleOfflinePacket((Packet)capturedPacketsListBox.SelectedItem);
            }
            
        }
    }
}
