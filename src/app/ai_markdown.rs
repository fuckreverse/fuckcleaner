//! Bounded, inert Markdown rendering. The parent owns integration and caching.

use std::ops::Range;

use gpui::{
    Div, FontStyle, FontWeight, HighlightStyle, SharedString, StrikethroughStyle, StyledText, div,
    prelude::*, px, rgb,
};
use palette::IntoColor;
use pulldown_cmark::{Alignment, CodeBlockKind, Event, Options, Parser, Tag, TagEnd};

use super::{ACCENT, BORDER, CARD, MUTED, PANEL, TEXT, WARNING};

const MAX_INPUT_BYTES: usize = 64 * 1024;
const MAX_EVENTS: usize = 16 * 1024;
const MAX_BLOCKS: usize = 1024;
const MAX_DEPTH: usize = 64;
// Reference destinations can be repeated many times without appearing in the source again.
const MAX_OUTPUT_BYTES: usize = 128 * 1024;
const MONO: &str = "Menlo";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct InlineStyle {
    bold: bool,
    italic: bool,
    strike: bool,
    code: bool,
    link: bool,
    literal: bool,
}

#[derive(Clone, Debug, Default)]
struct RichText {
    text: String,
    // Sorted, disjoint UTF-8 byte ranges; combined styles never overlap.
    spans: Vec<(Range<usize>, InlineStyle)>,
}

impl RichText {
    fn push(&mut self, text: &str, style: InlineStyle) {
        if text.is_empty() {
            return;
        }
        let start = self.text.len();
        self.text.push_str(text);
        if let Some((range, previous)) = self.spans.last_mut()
            && *previous == style
        {
            range.end = self.text.len();
            return;
        }
        self.spans.push((start..self.text.len(), style));
    }

    fn render(&self) -> StyledText {
        StyledText::new(self.text.clone())
            .with_highlights(self.spans.iter().map(|(range, style)| {
                let highlight = HighlightStyle {
                    font_weight: style.bold.then_some(FontWeight::BOLD),
                    font_style: style.italic.then_some(FontStyle::Italic),
                    strikethrough: style.strike.then_some(StrikethroughStyle {
                        thickness: px(1.),
                        color: None,
                    }),
                    background_color: style.code.then(|| rgb(CARD).into_color()),
                    color: if style.literal {
                        Some(rgb(MUTED).into_color())
                    } else if style.link || style.code {
                        Some(rgb(ACCENT).into_color())
                    } else {
                        None
                    },
                    ..Default::default()
                };
                (range.clone(), highlight)
            }))
            .with_font_family_overrides(
                self.spans
                    .iter()
                    .filter(|(_, style)| style.code)
                    .map(|(range, _)| (range.clone(), SharedString::from(MONO))),
            )
    }
}

#[derive(Clone, Debug, PartialEq)]
enum BlockKind {
    Root,
    Paragraph,
    Heading(u8),
    Quote,
    List,
    Item(String),
    Code(String),
    Html,
    Rule,
    Table,
    Row(bool),
    Cell(Alignment),
}

#[derive(Clone, Debug)]
struct Block {
    kind: BlockKind,
    text: RichText,
    children: Vec<usize>,
}

/// Owned parse result, suitable for caching by the parent instead of reparsing each frame.
#[derive(Clone, Debug)]
pub(super) struct MarkdownDocument {
    blocks: Vec<Block>,
    truncated: bool,
}

impl MarkdownDocument {
    pub(super) fn parse(text: &str) -> Self {
        let end = utf8_prefix(text, MAX_INPUT_BYTES);
        let mut builder = Builder::new(end < text.len());
        let options =
            Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH | Options::ENABLE_TASKLISTS;
        // Bound input before constructing the standard parser (including its internal tree).
        let mut parser = Parser::new_ext(&text[..end], options);
        for _ in 0..MAX_EVENTS {
            let Some(event) = parser.next() else {
                return builder.document;
            };
            if !builder.event(event) {
                builder.document.truncated = true;
                return builder.document;
            }
        }
        builder.document.truncated |= parser.next().is_some();
        builder.document
    }

    pub(super) fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Build inert GPUI elements; no app context, network, files or click callbacks.
    pub(super) fn render(&self) -> Div {
        // Children always have larger arena indices than their parent. Build bottom-up
        // to avoid large recursive GPUI builder frames on deeply nested untrusted input.
        let mut rendered: Vec<Option<Div>> = (0..self.blocks.len()).map(|_| None).collect();
        for index in (0..self.blocks.len()).rev() {
            let children = self.blocks[index]
                .children
                .iter()
                .map(|&child| rendered[child].take().unwrap())
                .collect();
            rendered[index] = Some(self.render_block(index, children));
        }
        let mut root = rendered[0].take().unwrap().text_sm().text_color(rgb(TEXT));
        if self.is_truncated() {
            root = root.child(
                div()
                    .text_xs()
                    .text_color(rgb(WARNING))
                    .child("[Markdown display limit reached]"),
            );
        }
        root
    }

    fn render_block(&self, index: usize, children: Vec<Div>) -> Div {
        let block = &self.blocks[index];
        let mut element = div()
            .min_w_0()
            .max_w_full()
            .whitespace_normal()
            .overflow_hidden();
        match &block.kind {
            BlockKind::Root => element = element.flex().flex_col().w_full().gap_2(),
            BlockKind::Paragraph => element = element.w_full(),
            BlockKind::Heading(level) => {
                let size = match level {
                    1 => 22.,
                    2 => 19.,
                    3 => 17.,
                    _ => 14.,
                };
                element = element
                    .w_full()
                    .text_size(px(size))
                    .font_weight(FontWeight::BOLD);
            }
            BlockKind::Quote => {
                element = element
                    .flex()
                    .flex_col()
                    .w_full()
                    .gap_2()
                    .pl_3()
                    .border_l_2()
                    .border_color(rgb(ACCENT))
                    .text_color(rgb(MUTED));
            }
            BlockKind::List => element = element.flex().flex_col().w_full().gap_1(),
            BlockKind::Item(marker) => {
                // A narrow marker and flexible body preserve indentation without constraining text.
                let body = div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .gap_1()
                    .when(!block.text.text.is_empty(), |body| {
                        body.child(block.text.render())
                    })
                    .children(children);
                return element
                    .flex()
                    .w_full()
                    .gap_2()
                    .child(
                        div()
                            .flex_none()
                            .min_w(px(24.))
                            .text_color(rgb(MUTED))
                            .child(marker.clone()),
                    )
                    .child(body);
            }
            BlockKind::Code(language) => {
                // GPUI text retains spaces/newlines; normal wrapping prevents long lines escaping.
                element = element
                    .flex()
                    .flex_col()
                    .w_full()
                    .gap_1()
                    .p_3()
                    .rounded_md()
                    .bg(rgb(PANEL))
                    .font_family(MONO);
                if !language.is_empty() {
                    element = element.child(
                        div()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child(language.clone()),
                    );
                }
            }
            BlockKind::Html => element = element.w_full().font_family(MONO).text_color(rgb(MUTED)),
            BlockKind::Rule => return element.w_full().h(px(1.)).my_2().bg(rgb(BORDER)),
            BlockKind::Table => {
                element = element
                    .flex()
                    .flex_col()
                    .w_full()
                    .border_1()
                    .border_color(rgb(BORDER))
                    .rounded_md();
            }
            BlockKind::Row(header) => {
                // Wrapped fixed-width cells bound wide GFM tables to the available panel width.
                element = element.flex().flex_wrap().w_full();
                if *header {
                    element = element.bg(rgb(CARD)).font_weight(FontWeight::BOLD);
                }
            }
            BlockKind::Cell(alignment) => {
                element = element
                    .w(px(160.))
                    .flex_none()
                    .p_2()
                    .border_b_1()
                    .border_color(rgb(BORDER));
                element = match alignment {
                    Alignment::Center => element.text_center(),
                    Alignment::Right => element.text_right(),
                    _ => element,
                };
            }
        }
        if !block.text.text.is_empty() {
            element = element.child(block.text.render());
        }
        element.children(children)
    }
}

pub(super) fn render_markdown(text: &str) -> gpui::Div {
    MarkdownDocument::parse(text).render()
}

fn utf8_prefix(text: &str, limit: usize) -> usize {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}

// Only display HTTP(S) destinations; all links remain non-interactive, including local hosts.
fn display_url(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"))
        && !rest.is_empty()
        && !rest.starts_with(['/', '?', '#'])
        && !url
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || ch == '\\')
}

struct Builder {
    document: MarkdownDocument,
    blocks: Vec<usize>,
    styles: Vec<InlineStyle>,
    links: Vec<Option<String>>,
    lists: Vec<Option<u64>>,
    alignments: Vec<Alignment>,
    column: usize,
    image_depth: usize,
    depth: usize,
    output_bytes: usize,
}

impl Builder {
    fn new(truncated: bool) -> Self {
        Self {
            document: MarkdownDocument {
                blocks: vec![Block {
                    kind: BlockKind::Root,
                    text: RichText::default(),
                    children: Vec::new(),
                }],
                truncated,
            },
            blocks: vec![0],
            styles: vec![InlineStyle::default()],
            links: Vec::new(),
            lists: Vec::new(),
            alignments: Vec::new(),
            column: 0,
            image_depth: 0,
            depth: 0,
            output_bytes: 0,
        }
    }

    fn open(&mut self, kind: BlockKind) -> bool {
        if self.document.blocks.len() >= MAX_BLOCKS {
            return false;
        }
        let index = self.document.blocks.len();
        self.document.blocks.push(Block {
            kind,
            text: RichText::default(),
            children: Vec::new(),
        });
        let parent = *self.blocks.last().unwrap();
        self.document.blocks[parent].children.push(index);
        self.blocks.push(index);
        true
    }

    fn push(&mut self, text: &str, style: InlineStyle) -> bool {
        let remaining = MAX_OUTPUT_BYTES - self.output_bytes;
        let end = utf8_prefix(text, remaining);
        let index = *self.blocks.last().unwrap();
        self.document.blocks[index].text.push(&text[..end], style);
        self.output_bytes += end;
        end == text.len()
    }

    fn event(&mut self, event: Event<'_>) -> bool {
        let style = *self.styles.last().unwrap();
        match event {
            Event::Start(tag) => {
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return false;
                }
                // Image contents are alt text only: do not interpret nested links/HTML as resources.
                if self.image_depth > 0 {
                    self.image_depth += 1;
                    return true;
                }
                match tag {
                    Tag::Paragraph => self.open(BlockKind::Paragraph),
                    Tag::Heading { level, .. } => self.open(BlockKind::Heading(level as u8)),
                    Tag::BlockQuote(_) => self.open(BlockKind::Quote),
                    Tag::List(start) => {
                        self.lists.push(start);
                        self.open(BlockKind::List)
                    }
                    Tag::Item => {
                        let marker = match self.lists.last_mut() {
                            Some(Some(next)) => {
                                let marker = format!("{next}.");
                                *next = next.saturating_add(1);
                                marker
                            }
                            _ => "•".to_owned(),
                        };
                        self.open(BlockKind::Item(marker))
                    }
                    Tag::CodeBlock(kind) => {
                        let language = match kind {
                            CodeBlockKind::Fenced(info) => {
                                info.split_whitespace().next().unwrap_or("").to_owned()
                            }
                            CodeBlockKind::Indented => String::new(),
                        };
                        self.open(BlockKind::Code(language))
                    }
                    Tag::HtmlBlock => self.open(BlockKind::Html),
                    Tag::Table(alignments) => {
                        self.alignments = alignments;
                        self.open(BlockKind::Table)
                    }
                    Tag::TableHead | Tag::TableRow => {
                        self.column = 0;
                        self.open(BlockKind::Row(matches!(tag, Tag::TableHead)))
                    }
                    Tag::TableCell => {
                        let alignment = self
                            .alignments
                            .get(self.column)
                            .copied()
                            .unwrap_or(Alignment::None);
                        self.column += 1;
                        self.open(BlockKind::Cell(alignment))
                    }
                    Tag::Emphasis | Tag::Strong | Tag::Strikethrough => {
                        let mut next = style;
                        match tag {
                            Tag::Emphasis => next.italic = true,
                            Tag::Strong => next.bold = true,
                            _ => next.strike = true,
                        }
                        self.styles.push(next);
                        true
                    }
                    Tag::Link { dest_url, .. } => {
                        let url = display_url(&dest_url).then(|| dest_url.into_string());
                        self.styles.push(InlineStyle {
                            link: url.is_some(),
                            ..style
                        });
                        self.links.push(url);
                        true
                    }
                    Tag::Image { .. } => {
                        self.image_depth = 1;
                        true
                    }
                    _ => true,
                }
            }
            Event::End(tag) => {
                self.depth = self.depth.saturating_sub(1);
                if self.image_depth > 0 {
                    self.image_depth -= 1;
                    return true;
                }
                match tag {
                    TagEnd::Emphasis | TagEnd::Strong | TagEnd::Strikethrough => {
                        self.styles.pop();
                    }
                    TagEnd::Link => {
                        self.styles.pop();
                        if let Some(Some(url)) = self.links.pop() {
                            return self.push(
                                &format!(" ({url})"),
                                InlineStyle {
                                    link: true,
                                    ..*self.styles.last().unwrap()
                                },
                            );
                        }
                    }
                    TagEnd::List(_) => {
                        self.lists.pop();
                        self.blocks.pop();
                    }
                    TagEnd::Paragraph
                    | TagEnd::Heading(_)
                    | TagEnd::BlockQuote(_)
                    | TagEnd::Item
                    | TagEnd::CodeBlock
                    | TagEnd::HtmlBlock
                    | TagEnd::Table
                    | TagEnd::TableHead
                    | TagEnd::TableRow
                    | TagEnd::TableCell => {
                        self.blocks.pop();
                    }
                    _ => {}
                }
                true
            }
            Event::Text(text) => self.push(&text, style),
            Event::Code(text) => self.push(
                &text,
                InlineStyle {
                    code: self.image_depth == 0,
                    ..style
                },
            ),
            Event::Html(text) | Event::InlineHtml(text) => self.push(
                &text,
                InlineStyle {
                    literal: true,
                    ..style
                },
            ),
            Event::SoftBreak => self.push(" ", style),
            Event::HardBreak => self.push("\n", style),
            Event::Rule => {
                if !self.open(BlockKind::Rule) {
                    return false;
                }
                self.blocks.pop();
                true
            }
            Event::TaskListMarker(checked) => {
                self.push(if checked { "[x] " } else { "[ ] " }, style)
            }
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(document: &MarkdownDocument) -> String {
        document
            .blocks
            .iter()
            .map(|block| block.text.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn headings_paragraphs_and_combined_inline_styles() {
        let doc = MarkdownDocument::parse("# 标题\n\nnormal **粗 *斜* 体** ~~删除~~ `代码`\n\n---");
        assert!(doc.blocks.iter().any(|b| b.kind == BlockKind::Heading(1)));
        assert!(doc.blocks.iter().any(|b| b.kind == BlockKind::Paragraph));
        assert!(doc.blocks.iter().any(|b| b.kind == BlockKind::Rule));
        let spans: Vec<_> = doc.blocks.iter().flat_map(|b| &b.text.spans).collect();
        assert!(spans.iter().any(|(_, s)| s.bold && s.italic));
        assert!(spans.iter().any(|(_, s)| s.strike));
        assert!(spans.iter().any(|(_, s)| s.code));
        assert!(!doc.is_truncated());
    }

    #[test]
    fn nested_ordered_unordered_lists_and_quotes() {
        let doc = MarkdownDocument::parse(
            "> 3. first\n>    - nested\n>    - second\n> 4. last\n\n- loose\n\n  paragraph",
        );
        let markers: Vec<_> = doc
            .blocks
            .iter()
            .filter_map(|b| {
                if let BlockKind::Item(marker) = &b.kind {
                    Some(marker.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(markers, ["3.", "•", "•", "4.", "•"]);
        let quote = doc
            .blocks
            .iter()
            .find(|b| b.kind == BlockKind::Quote)
            .unwrap();
        assert!(
            quote
                .children
                .iter()
                .any(|&i| doc.blocks[i].kind == BlockKind::List)
        );
        let first = doc
            .blocks
            .iter()
            .find(|b| b.kind == BlockKind::Item("3.".into()))
            .unwrap();
        assert!(
            first
                .children
                .iter()
                .any(|&i| doc.blocks[i].kind == BlockKind::List)
        );
    }

    #[test]
    fn code_preserves_whitespace_and_never_executes() {
        let doc = MarkdownDocument::parse(
            "```sh\n  rm -rf /\n\t<script>danger</script>\n```\n\n    indented\n",
        );
        let code = doc
            .blocks
            .iter()
            .find(|b| b.kind == BlockKind::Code("sh".into()))
            .unwrap();
        assert_eq!(code.text.text, "  rm -rf /\n\t<script>danger</script>\n");
        assert!(
            doc.blocks
                .iter()
                .any(|b| b.kind == BlockKind::Code(String::new()))
        );
    }

    #[test]
    fn gfm_table_alignment_and_styled_cells() {
        let doc = MarkdownDocument::parse(
            "| left | center | right |\n| :--- | :---: | ---: |\n| **a** | 中文 | `c` |\n",
        );
        assert!(doc.blocks.iter().any(|b| b.kind == BlockKind::Table));
        assert!(doc.blocks.iter().any(|b| b.kind == BlockKind::Row(true)));
        assert!(
            doc.blocks
                .iter()
                .any(|b| b.kind == BlockKind::Cell(Alignment::Center))
        );
        assert!(
            doc.blocks
                .iter()
                .any(|b| b.kind == BlockKind::Cell(Alignment::Right))
        );
        assert!(
            doc.blocks
                .iter()
                .any(|b| b.text.spans.iter().any(|(_, s)| s.bold))
        );
    }

    #[test]
    fn html_is_literal_images_are_alt_and_unsafe_links_have_no_destination() {
        let doc = MarkdownDocument::parse(
            "<script>alert('x')</script>\n\n<img src=\"file:///secret\">\n\n![**alt** `文字`](https://tracking.invalid/pixel) [bad](javascript:alert%281%29) [file](file:///secret) [data](data:text/html,evil) [ok](https://example.com/path) [ref][r]\n\n[r]: http://example.org",
        );
        let text = plain(&doc);
        assert!(text.contains("<script>alert('x')</script>"));
        assert!(text.contains("<img src=\"file:///secret\">"));
        assert!(text.contains("alt 文字"));
        assert!(!text.contains("tracking.invalid"));
        assert!(!text.contains("javascript:"));
        assert!(!text.contains("data:text"));
        assert!(text.contains("ok (https://example.com/path)"));
        assert!(text.contains("ref (http://example.org)"));
        let files = MarkdownDocument::parse("[file](file:///secret) ![alt](file:///secret)");
        assert!(!plain(&files).contains("file:"));
    }

    #[test]
    fn url_policy_and_unicode_ranges() {
        for url in [
            "javascript:alert(1)",
            "file:///tmp/a",
            "data:text/html,x",
            "//example.com",
            "https://",
            "https:///x",
            "https://a\\b",
            "https://a\nb",
        ] {
            assert!(!display_url(url), "{url:?}");
        }
        assert!(display_url("HTTPS://example.com/中文"));
        let doc =
            MarkdownDocument::parse("👩‍💻 **你好 *é* 世界** ~~🦀~~ `λ` [链接](https://example.com)");
        for block in &doc.blocks {
            let mut end = 0;
            for (range, _) in &block.text.spans {
                assert_eq!(range.start, end);
                assert!(block.text.text.is_char_boundary(range.start));
                assert!(block.text.text.is_char_boundary(range.end));
                end = range.end;
            }
            assert_eq!(end, block.text.text.len());
        }
    }

    #[test]
    fn input_blocks_depth_and_event_limits() {
        let doc = MarkdownDocument::parse(&"🦀".repeat(MAX_INPUT_BYTES));
        assert!(doc.is_truncated());
        assert!(plain(&doc).len() <= MAX_INPUT_BYTES + MAX_BLOCKS);
        let doc = MarkdownDocument::parse(&"x\n\n".repeat(MAX_BLOCKS * 2));
        assert!(doc.is_truncated());
        assert_eq!(doc.blocks.len(), MAX_BLOCKS);
        let doc = MarkdownDocument::parse(&format!("{}x", "> ".repeat(MAX_DEPTH + 1)));
        assert!(doc.is_truncated());
        assert!(doc.blocks.len() <= MAX_DEPTH + 1);
        let input = "*x* ".repeat(5000);
        assert!(input.len() < MAX_INPUT_BYTES);
        assert!(Parser::new_ext(&input, Options::empty()).count() > MAX_EVENTS);
        let doc = MarkdownDocument::parse(&input);
        assert!(doc.is_truncated());
        assert!(doc.blocks.len() <= MAX_BLOCKS);
    }

    #[test]
    fn repeated_reference_destinations_have_bounded_output() {
        // The standard parser itself caps reference expansion at 100,000 bytes.
        // A large literal prefix plus expanded links exercises our additional total budget.
        let input = format!(
            "{} {}\n\n[r]: https://example.com/{}",
            "z".repeat(40_000),
            "[x][r] ".repeat(2000),
            "a".repeat(2000)
        );
        let doc = MarkdownDocument::parse(&input);
        assert!(doc.is_truncated());
        assert!(doc.blocks.iter().map(|b| b.text.text.len()).sum::<usize>() <= MAX_OUTPUT_BYTES);
    }

    #[test]
    fn utf8_truncation_at_partial_character_and_exact_limit() {
        let input = format!("{}🦀", "a".repeat(MAX_INPUT_BYTES - 1));
        let doc = MarkdownDocument::parse(&input);
        assert!(doc.is_truncated());
        assert_eq!(doc.blocks[1].text.text.len(), MAX_INPUT_BYTES - 1);
        assert!(!MarkdownDocument::parse(&"a".repeat(MAX_INPUT_BYTES)).is_truncated());
    }

    #[test]
    fn breaks_task_markers_inline_html_and_image_nested_links() {
        let doc = MarkdownDocument::parse(
            "first\nsecond  \nthird <b>raw</b>\n\n- [x] done\n- [ ] todo\n\n![alt [nested](https://hidden.invalid)](file:///image)",
        );
        let text = plain(&doc);
        assert!(text.contains("first second\nthird <b>raw</b>"));
        assert!(text.contains("[x] done"));
        assert!(text.contains("[ ] todo"));
        assert!(text.contains("alt nested"));
        assert!(!text.contains("hidden.invalid"));
        assert!(!text.contains("file:///image"));
    }

    #[test]
    fn adversarial_tables_and_partial_documents_can_render() {
        let wide = format!(
            "{}\n{}\n{}",
            "| a ".repeat(300),
            "| --- ".repeat(300),
            "| 🦀 ".repeat(300)
        );
        let sparse = format!(
            "{}\n{}\n{}",
            "| a ".repeat(200),
            "| --- ".repeat(200),
            "| x\n".repeat(200)
        );
        for input in [
            wide,
            sparse,
            "> ".repeat(1000),
            "*x* ".repeat(20_000),
            "x\n\n".repeat(2000),
        ] {
            let doc = MarkdownDocument::parse(&input);
            assert!(doc.blocks.len() <= MAX_BLOCKS);
            assert!(
                doc.blocks.iter().map(|b| b.text.text.len()).sum::<usize>() <= MAX_OUTPUT_BYTES
            );
            let _element = doc.render();
        }
    }

    #[test]
    fn empty_unclosed_markdown_and_renderer_need_no_context() {
        for input in [
            "",
            "**unfinished",
            "```rust\n  let x = 1;",
            "| a | b |\n|---|---|\n|长长长|text|",
            "> - **quote**",
        ] {
            let doc = MarkdownDocument::parse(input);
            let _element = doc.render();
            let _element = render_markdown(input);
        }
    }
}
