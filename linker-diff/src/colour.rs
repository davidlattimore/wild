use clap::ValueEnum;
use std::sync::LazyLock;

#[derive(ValueEnum, Copy, Clone, Default)]
pub enum ColourMode {
    #[default]
    Auto,
    Never,
    Always,
}

impl ColourMode {
    pub(crate) fn is_enabled(self) -> bool {
        match self {
            ColourMode::Auto => stdout_is_terminal(),
            ColourMode::Never => false,
            ColourMode::Always => true,
        }
    }

    fn style<T: std::fmt::Display>(self, text: T, style: anstyle::Style) -> Painted<T> {
        Painted {
            text,
            style,
            enabled: self.is_enabled(),
        }
    }

    fn colour<T: std::fmt::Display>(self, text: T, colour: anstyle::AnsiColor) -> Painted<T> {
        self.style(
            text,
            anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(colour))),
        )
    }

    pub(crate) fn red<T: std::fmt::Display>(self, text: T) -> Painted<T> {
        self.colour(text, anstyle::AnsiColor::Red)
    }

    pub(crate) fn green<T: std::fmt::Display>(self, text: T) -> Painted<T> {
        self.colour(text, anstyle::AnsiColor::Green)
    }

    pub(crate) fn green_bold<T: std::fmt::Display>(self, text: T) -> Painted<T> {
        self.colour(text, anstyle::AnsiColor::Green).bold()
    }

    pub(crate) fn bright_green<T: std::fmt::Display>(self, text: T) -> Painted<T> {
        self.colour(text, anstyle::AnsiColor::BrightGreen)
    }

    pub(crate) fn blue<T: std::fmt::Display>(self, text: T) -> Painted<T> {
        self.colour(text, anstyle::AnsiColor::Blue)
    }

    pub(crate) fn yellow<T: std::fmt::Display>(self, text: T) -> Painted<T> {
        self.colour(text, anstyle::AnsiColor::Yellow)
    }

    pub(crate) fn bright_yellow<T: std::fmt::Display>(self, text: T) -> Painted<T> {
        self.colour(text, anstyle::AnsiColor::BrightYellow)
    }

    pub(crate) fn cyan<T: std::fmt::Display>(self, text: T) -> Painted<T> {
        self.colour(text, anstyle::AnsiColor::Cyan)
    }

    pub(crate) fn magenta<T: std::fmt::Display>(self, text: T) -> Painted<T> {
        self.colour(text, anstyle::AnsiColor::Magenta)
    }
}

fn stdout_is_terminal() -> bool {
    static CACHED_VALUE: LazyLock<bool> =
        LazyLock::new(|| std::io::IsTerminal::is_terminal(&std::io::stdout()));

    *CACHED_VALUE
}

/// Wraps a value with an ANSI style for display, applying the style only when colour is enabled.
pub(crate) struct Painted<T: std::fmt::Display> {
    text: T,
    style: anstyle::Style,
    enabled: bool,
}

impl<T: std::fmt::Display> Painted<T> {
    fn bold(mut self) -> Self {
        self.style = self.style.effects(anstyle::Effects::BOLD);
        self
    }
}

impl<T: std::fmt::Display> std::fmt::Display for Painted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.enabled {
            write!(
                f,
                "{}{}{}",
                self.style.render(),
                self.text,
                self.style.render_reset()
            )
        } else {
            self.text.fmt(f)
        }
    }
}
