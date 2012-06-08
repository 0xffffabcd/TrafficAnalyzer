using System.Collections.Generic;
using System.Windows;
using MahApps.Metro.Controls;
using PcapDotNet.Core;
using PcapDotNet.Core.Extensions;

namespace TrafficAnalyzer
{
    /// <summary>
    /// Interaction logic for SelectInterfaceDialog.xaml
    /// </summary>
    public partial class SelectInterfaceDialog : MetroWindow
    {
        private IList<LivePacketDevice> _devices;
        public IPacketDevice SelectedDevice;

        public SelectInterfaceDialog()
        {
            InitializeComponent();
        }

        private void WindowLoaded(object sender, RoutedEventArgs e)
        {
            _devices = LivePacketDevice.AllLocalMachine;
            interfacesComboBox.DataContext = _devices;

            if (_devices.Count == 0)
            {
                MessageBox.Show("No capture interface available", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SelectButtonClick(object sender, RoutedEventArgs e)
        {
            SelectedDevice = (IPacketDevice) interfacesComboBox.SelectedItem;
            DialogResult = true;
            Close();
        }

        private void CancelButtonClick(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void InterfacesComboBoxSelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            MACAddressLabel.Content = 
                string.Format("Mac Address : {0}",((LivePacketDevice) interfacesComboBox.SelectedItem).GetMacAddress());
            OperationStatusLabel.Content =
                string.Format("Operational Status : {0}",
                              ((LivePacketDevice) interfacesComboBox.SelectedItem).GetNetworkInterface().OperationalStatus);
            InterfaceTypeLabel.Content = string.Format("Interface Type : {0}",
                                           ((LivePacketDevice) interfacesComboBox.SelectedItem).GetNetworkInterface().NetworkInterfaceType  );


        }
    }
}
