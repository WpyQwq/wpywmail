using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;

namespace WpywMail.Client;

public sealed class UnreadBackgroundConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is true ? Application.Current.Resources["AccentSubtleBrush"] : Application.Current.Resources["SurfaceBrush"];

    public object ConvertBack(object value, Type targetType, object parameter, string language) => throw new NotSupportedException();
}

public sealed class UnreadWeightConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language) =>
        value is true ? Microsoft.UI.Text.FontWeights.SemiBold : Microsoft.UI.Text.FontWeights.Normal;

    public object ConvertBack(object value, Type targetType, object parameter, string language) => throw new NotSupportedException();
}
