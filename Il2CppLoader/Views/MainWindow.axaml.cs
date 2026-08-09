using System;
using System.Globalization;
using Avalonia.Data.Converters;
using Avalonia.Markup.Xaml;
using Avalonia.Media;

namespace Il2CppLoader.Views;

public partial class MainWindow : Avalonia.Controls.Window
{
    public MainWindow()
    {
        AvaloniaXamlLoader.Load(this);
    }
}

/// <summary>Colors the WIN/LNX/WINE tag in the process list.</summary>
public sealed class KindBrushConverter : IValueConverter
{
    public static readonly KindBrushConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value as string switch
        {
            "WINE" => new SolidColorBrush(Color.Parse("#f9e2af")),
            "LNX" => new SolidColorBrush(Color.Parse("#a6e3a1")),
            _ => new SolidColorBrush(Color.Parse("#89b4fa")),
        };

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
