using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;

namespace DisasmStudio.Wpf.Controls;

/// <summary>
/// A ToolBar whose overflow acts as a pinned command palette: activating an overflow
/// command does not dismiss the palette. Only the overflow toggle dismisses it.
/// </summary>
public sealed class PersistentToolBar : ToolBar
{
    private static readonly CoerceValueCallback? BaseCoerceOverflowOpen;

    private ToggleButton? _overflowButton;
    private ToolBarOverflowPanel? _overflowPanel;
    private bool _syncingOverflowButton;
    private bool _explicitToggleChange;
    private bool _keepOverflowOpen;

    static PersistentToolBar()
    {
        // Preserve ToolBar's own validation (notably, it will not open without overflow
        // items), then add the pinned-state rule below.
        BaseCoerceOverflowOpen =
            IsOverflowOpenProperty.GetMetadata(typeof(ToolBar)).CoerceValueCallback;
        IsOverflowOpenProperty.OverrideMetadata(
            typeof(PersistentToolBar),
            new FrameworkPropertyMetadata(
                false,
                FrameworkPropertyMetadataOptions.BindsTwoWayByDefault,
                propertyChangedCallback: null,
                coerceValueCallback: CoerceOverflowOpen));

        // ToolBar's base class handler closes overflow after any direct ButtonBase item
        // clicks. A derived class handler runs first; handling only true overflow items
        // leaves each button's own Click callback intact while suppressing that dismissal.
        EventManager.RegisterClassHandler(
            typeof(PersistentToolBar),
            ButtonBase.ClickEvent,
            new RoutedEventHandler(OnOverflowItemClick));
    }

    public override void OnApplyTemplate()
    {
        if (_overflowButton is not null)
        {
            _overflowButton.Checked -= OnOverflowButtonChanged;
            _overflowButton.Unchecked -= OnOverflowButtonChanged;
            _overflowButton.PreviewMouseLeftButtonDown -= OnOverflowButtonPreviewMouseLeftButtonDown;
            _overflowButton.PreviewKeyDown -= OnOverflowButtonPreviewKeyDown;
        }
        if (_overflowPanel is not null)
            _overflowPanel.PreviewKeyDown -= OnOverflowPanelPreviewKeyDown;

        base.OnApplyTemplate();

        _overflowButton = GetTemplateChild("OverflowButton") as ToggleButton;
        _overflowPanel = GetTemplateChild("PART_ToolBarOverflowPanel") as ToolBarOverflowPanel;
        if (_overflowPanel is not null)
            _overflowPanel.PreviewKeyDown += OnOverflowPanelPreviewKeyDown;
        if (_overflowButton is not null)
        {
            SyncOverflowButton(IsOverflowOpen);
            _overflowButton.Checked += OnOverflowButtonChanged;
            _overflowButton.Unchecked += OnOverflowButtonChanged;
            _overflowButton.PreviewMouseLeftButtonDown += OnOverflowButtonPreviewMouseLeftButtonDown;
            _overflowButton.PreviewKeyDown += OnOverflowButtonPreviewKeyDown;
        }
    }

    protected override void OnPropertyChanged(DependencyPropertyChangedEventArgs e)
    {
        base.OnPropertyChanged(e);
        if (e.Property != IsOverflowOpenProperty) return;

        bool isOpen = (bool)e.NewValue;
        SyncOverflowButton(isOpen);

        if (isOpen)
            _keepOverflowOpen = true;
    }

    private static object CoerceOverflowOpen(DependencyObject d, object baseValue)
    {
        object value = BaseCoerceOverflowOpen?.Invoke(d, baseValue) ?? baseValue;
        if (d is PersistentToolBar toolbar &&
            value is false &&
            toolbar._keepOverflowOpen &&
            !toolbar._explicitToggleChange &&
            toolbar.IsLoaded)
        {
            // Reject ToolBar's automatic dismissals synchronously. Keeping the effective
            // value true avoids the close/reopen frame that made the palette flicker.
            return true;
        }

        return value;
    }

    private static void OnOverflowItemClick(object sender, RoutedEventArgs e)
    {
        if (sender is PersistentToolBar { IsOverflowOpen: true } &&
            e.OriginalSource is ButtonBase button &&
            GetIsOverflowItem(button))
        {
            e.Handled = true;
        }
    }

    private void OnOverflowButtonChanged(object sender, RoutedEventArgs e)
    {
        if (_syncingOverflowButton || _overflowButton is null) return;

        _explicitToggleChange = true;
        _keepOverflowOpen = _overflowButton.IsChecked == true;
        SetCurrentValue(IsOverflowOpenProperty, _keepOverflowOpen);
        CoerceValue(IsOverflowOpenProperty);
        _explicitToggleChange = false;
    }

    private void OnOverflowButtonPreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (!IsOverflowOpen) return;

        // ToolBar's mouse-down handler closes first; without consuming this gesture the
        // ToggleButton's later mouse-up would check itself and immediately reopen.
        _explicitToggleChange = true;
        _keepOverflowOpen = false;
        SetCurrentValue(IsOverflowOpenProperty, false);
        CoerceValue(IsOverflowOpenProperty);
        _explicitToggleChange = false;
        e.Handled = true;
    }

    private void OnOverflowButtonPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (!IsOverflowOpen || _overflowPanel is null) return;

        FocusNavigationDirection? direction = e.Key switch
        {
            Key.Tab when Keyboard.Modifiers.HasFlag(ModifierKeys.Shift) => FocusNavigationDirection.Last,
            Key.Tab => FocusNavigationDirection.First,
            Key.Down => FocusNavigationDirection.First,
            Key.Up => FocusNavigationDirection.Last,
            _ => null,
        };
        if (direction is null) return;

        e.Handled = _overflowPanel.MoveFocus(new TraversalRequest(direction.Value));
    }

    private void OnOverflowPanelPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Escape) return;

        _explicitToggleChange = true;
        _keepOverflowOpen = false;
        SetCurrentValue(IsOverflowOpenProperty, false);
        CoerceValue(IsOverflowOpenProperty);
        _explicitToggleChange = false;
        _overflowButton?.Focus();
        e.Handled = true;
    }

    private void SyncOverflowButton(bool isOpen)
    {
        if (_overflowButton is null || _overflowButton.IsChecked == isOpen) return;

        _syncingOverflowButton = true;
        _overflowButton.SetCurrentValue(ToggleButton.IsCheckedProperty, isOpen);
        _syncingOverflowButton = false;
    }
}
