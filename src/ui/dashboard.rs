use crate::ui::App;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use std::io;
use std::time::Duration;

pub async fn run_ui(mut app: App) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        eprintln!("Error: {err:?}");
    }

    Ok(())
}

fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()>
where
    <B as ratatui::backend::Backend>::Error: Send + Sync + 'static,
{
    let mut table_state = TableState::default();

    loop {
        terminal.draw(|f| ui(f, app, &mut table_state))?;

        if event::poll(Duration::from_millis(100))?
            && let Event::Key(key) = event::read()?
        {
            match key.code {
                KeyCode::Char('q') => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                _ => {}
            }

            if app.filter_mode {
                match key.code {
                    KeyCode::Enter => {
                        app.apply_filter();
                    }
                    KeyCode::Esc => {
                        app.exit_filter_mode();
                    }
                    KeyCode::Backspace => {
                        app.filter_backspace();
                    }
                    KeyCode::Char(c) => {
                        app.filter_input_char(c);
                    }
                    _ => {}
                }
                continue;
            }

            match key.code {
                KeyCode::Char('s') => app.toggle_sort(),
                KeyCode::Char('/') => {
                    app.enter_filter_mode();
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    app.scroll_up();
                    table_state.select(Some(app.scroll_state));
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let filter = if app.filter.is_empty() {
                        None
                    } else {
                        Some(app.filter.as_str())
                    };
                    let queries = app.dns_state.get_queries(app.sort_by, filter);
                    app.scroll_down(queries.len());
                    table_state.select(Some(app.scroll_state));
                }
                KeyCode::PageUp => {
                    app.page_up();
                    table_state.select(Some(app.scroll_state));
                }
                KeyCode::PageDown => {
                    let filter = if app.filter.is_empty() {
                        None
                    } else {
                        Some(app.filter.as_str())
                    };
                    let queries = app.dns_state.get_queries(app.sort_by, filter);
                    app.page_down(queries.len());
                    table_state.select(Some(app.scroll_state));
                }
                KeyCode::Home => {
                    app.home();
                    table_state.select(Some(app.scroll_state));
                }
                KeyCode::End => {
                    let filter = if app.filter.is_empty() {
                        None
                    } else {
                        Some(app.filter.as_str())
                    };
                    let queries = app.dns_state.get_queries(app.sort_by, filter);
                    app.end(queries.len());
                    table_state.select(Some(app.scroll_state));
                }
                _ => {}
            }
        }
    }

    Ok(())
}

fn ui(f: &mut Frame, app: &App, table_state: &mut TableState) {
    let chunks = if app.filter_mode {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .split(f.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
            ])
            .split(f.area())
    };

    render_header(f, chunks[0], app);
    render_table(f, chunks[1], app, table_state);

    if app.filter_mode {
        render_filter_input(f, chunks[2], app);
        render_footer(f, chunks[3], app);
    } else {
        render_footer(f, chunks[2], app);
    }
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let (total_domains, total_queries) = app.dns_state.stats();

    let title = Line::from(vec![
        Span::styled("DNS Query Monitor", Style::default().fg(Color::Cyan).bold()),
        Span::raw(" | "),
        Span::styled(
            format!("Domains: {total_domains}"),
            Style::default().fg(Color::Green),
        ),
        Span::raw(" | "),
        Span::styled(
            format!("Queries: {total_queries}"),
            Style::default().fg(Color::Yellow),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White));

    let paragraph = Paragraph::new(title).block(block);
    f.render_widget(paragraph, area);
}

fn render_table(f: &mut Frame, area: Rect, app: &App, table_state: &mut TableState) {
    let filter_opt = if app.filter.is_empty() {
        None
    } else {
        Some(app.filter.as_str())
    };

    let queries = app.dns_state.get_queries(app.sort_by, filter_opt);

    let header_cells = [
        "Domain",
        "Source IP",
        "Type",
        "Answer",
        "Last Query",
        "Count",
    ]
    .iter()
    .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).bold()));

    let header = Row::new(header_cells)
        .style(Style::default().bg(Color::DarkGray))
        .height(1);

    let rows = queries.iter().map(|query| {
        let cells = vec![
            Cell::from(query.domain.clone()),
            Cell::from(query.src_ip_list()),
            Cell::from(query.query_type_list()),
            Cell::from(query.answer_list()),
            Cell::from(query.last_query.format("%Y-%m-%d %H:%M:%S").to_string()),
            Cell::from(query.count.to_string()),
        ];
        Row::new(cells).height(1)
    });

    let sort_indicator = match app.sort_by {
        crate::dns::SortBy::LastQuery => " [Sort: Time ↓]",
        crate::dns::SortBy::Count => " [Sort: Count ↓]",
        crate::dns::SortBy::Domain => " [Sort: Domain ↑]",
    };

    let title = if app.filter.is_empty() {
        format!("DNS Queries{sort_indicator}")
    } else {
        format!("DNS Queries{} [Filter: {}]", sort_indicator, app.filter)
    };

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(25),
            Constraint::Percentage(15),
            Constraint::Percentage(10),
            Constraint::Percentage(25),
            Constraint::Percentage(15),
            Constraint::Percentage(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::White)),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );

    f.render_stateful_widget(table, area, table_state);
}

fn render_filter_input(f: &mut Frame, area: Rect, app: &App) {
    let input_text = Line::from(vec![
        Span::styled("Filter: ", Style::default().fg(Color::Yellow).bold()),
        Span::raw(&app.filter_input),
        Span::styled("█", Style::default().fg(Color::Green)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Enter filter pattern (Enter to apply, Esc to cancel)")
        .border_style(Style::default().fg(Color::Green));

    let paragraph = Paragraph::new(input_text).block(block);
    f.render_widget(paragraph, area);
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let help_text = if app.filter_mode {
        Line::from(vec![
            Span::styled("Enter", Style::default().fg(Color::Cyan)),
            Span::raw(" Apply | "),
            Span::styled("Esc", Style::default().fg(Color::Cyan)),
            Span::raw(" Cancel | "),
            Span::styled("Backspace", Style::default().fg(Color::Cyan)),
            Span::raw(" Delete"),
        ])
    } else {
        Line::from(vec![
            Span::styled("q/Ctrl+C", Style::default().fg(Color::Cyan)),
            Span::raw(" Quit | "),
            Span::styled("/", Style::default().fg(Color::Cyan)),
            Span::raw(" Filter | "),
            Span::styled("s", Style::default().fg(Color::Cyan)),
            Span::raw(" Sort | "),
            Span::styled("↑↓/jk", Style::default().fg(Color::Cyan)),
            Span::raw(" Navigate"),
        ])
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White));

    let paragraph = Paragraph::new(help_text).block(block);
    f.render_widget(paragraph, area);
}
