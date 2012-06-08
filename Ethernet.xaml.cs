using System.Windows.Controls;
using PcapDotNet.Packets.Ethernet;

namespace TrafficAnalyzer
{
    /// <summary>
    /// Interaction logic for Ethernet.xaml
    /// </summary>
    public partial class Ethernet : UserControl
    {
        private EthernetDatagram _datagram;
        public EthernetDatagram Datagram
        {
            get { return _datagram; }
            set
            {
                _datagram = value;

                if (value != null)
                {
                    containerGrid.DataContext = Datagram;
                }
            }
        }

        public Ethernet()
        {
            InitializeComponent();
        }

        private void UserControlLoaded(object sender, System.Windows.RoutedEventArgs e)
        {

        }



    }
}
