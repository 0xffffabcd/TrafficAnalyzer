using System;
using System.Globalization;
using System.Windows.Data;
using PcapDotNet.Packets.Ethernet;

namespace TrafficAnalyzer
{
    class EtherTypeConverter:IValueConverter 
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value != null)
            {
                return ((EthernetType) value).ToString();
            }
            return string.Empty;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
