use crate::error::{AppError, Result};
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
};
use ratatui::DefaultTerminal;

pub fn error(e: impl ToString) -> AppError {
    AppError::new("terminal", e.to_string())
}
pub struct Session {
    pub terminal: Option<DefaultTerminal>,
}
impl Session {
    pub fn enter() -> Result<Self> {
        let mut session = Self { terminal: None };
        session.resume()?;
        Ok(session)
    }
    pub fn resume(&mut self) -> Result<()> {
        if self.terminal.is_some() {
            return Ok(());
        }
        match ratatui::try_init() {
            Ok(t) => self.terminal = Some(t),
            Err(e) => {
                ratatui::restore();
                return Err(error(e));
            }
        }
        if let Err(e) = execute!(std::io::stdout(), EnableMouseCapture) {
            self.suspend();
            return Err(error(e));
        }
        execute!(
            std::io::stdout(),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
            crossterm::cursor::MoveTo(0, 0)
        )
        .map_err(error)?;
        Ok(())
    }
    pub fn suspend(&mut self) {
        if self.terminal.take().is_some() {
            let _ = execute!(std::io::stdout(), DisableMouseCapture);
            ratatui::restore();
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.suspend();
    }
}
