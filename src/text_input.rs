use std::ops::Range;

use gpui::{
    App, Bounds, ClipboardItem, ContentMask, Context, CursorStyle, DispatchPhase, Element,
    ElementInputHandler, Entity, EntityInputHandler, FocusHandle, Focusable, LayoutId, PaintQuad,
    Pixels, Point, ShapedLine, SharedString, TextAlign, TextRun, UTF16Selection, Window, actions,
    div, fill, point, prelude::*, px, relative, rgb, rgb_to_hsla, rgba, size,
};

const MASK: &str = "•";

actions!(
    petal_text_input,
    [
        Left,
        Right,
        Home,
        End,
        SelectLeft,
        SelectRight,
        SelectHome,
        SelectEnd,
        Backspace,
        Delete,
        DeleteToStart,
        SelectAll,
        Copy,
        Cut,
        Paste,
    ]
);

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        gpui::KeyBinding::new("left", Left, Some("TextInput")),
        gpui::KeyBinding::new("right", Right, Some("TextInput")),
        gpui::KeyBinding::new("up", Home, Some("TextInput")),
        gpui::KeyBinding::new("down", End, Some("TextInput")),
        gpui::KeyBinding::new("home", Home, Some("TextInput")),
        gpui::KeyBinding::new("end", End, Some("TextInput")),
        gpui::KeyBinding::new("cmd-left", Home, Some("TextInput")),
        gpui::KeyBinding::new("cmd-right", End, Some("TextInput")),
        gpui::KeyBinding::new("shift-left", SelectLeft, Some("TextInput")),
        gpui::KeyBinding::new("shift-right", SelectRight, Some("TextInput")),
        gpui::KeyBinding::new("shift-up", SelectHome, Some("TextInput")),
        gpui::KeyBinding::new("shift-down", SelectEnd, Some("TextInput")),
        gpui::KeyBinding::new("shift-home", SelectHome, Some("TextInput")),
        gpui::KeyBinding::new("shift-end", SelectEnd, Some("TextInput")),
        gpui::KeyBinding::new("cmd-shift-left", SelectHome, Some("TextInput")),
        gpui::KeyBinding::new("cmd-shift-right", SelectEnd, Some("TextInput")),
        gpui::KeyBinding::new("backspace", Backspace, Some("TextInput")),
        gpui::KeyBinding::new("delete", Delete, Some("TextInput")),
        gpui::KeyBinding::new("cmd-backspace", DeleteToStart, Some("TextInput")),
        gpui::KeyBinding::new("cmd-a", SelectAll, Some("TextInput")),
        gpui::KeyBinding::new("cmd-c", Copy, Some("TextInput")),
        gpui::KeyBinding::new("cmd-x", Cut, Some("TextInput")),
        gpui::KeyBinding::new("cmd-v", Paste, Some("TextInput")),
    ]);
}

pub struct TextInput {
    value: String,
    edit_revision: u64,
    placeholder: String,
    masked: bool,
    focus: FocusHandle,
    // Both endpoints are UTF-8 byte boundaries. Keeping the anchor preserves
    // selection direction when extending or crossing it with Shift/drag.
    anchor: usize,
    cursor: usize,
    marked: Option<Range<usize>>,
    dragging: bool,
    scroll_x: Pixels,
    layout: Option<InputLayout>,
}

#[derive(Clone)]
struct InputLayout {
    line: ShapedLine,
    bounds: Bounds<Pixels>,
    origin: Point<Pixels>,
}

impl TextInput {
    pub fn new(
        value: impl Into<String>,
        placeholder: impl Into<String>,
        masked: bool,
        cx: &mut Context<Self>,
    ) -> Self {
        let value = single_line(&value.into());
        let cursor = value.len();
        Self {
            value,
            edit_revision: 0,
            placeholder: single_line(&placeholder.into()),
            masked,
            focus: cx.focus_handle(),
            anchor: cursor,
            cursor,
            marked: None,
            dragging: false,
            scroll_x: px(0.),
            layout: None,
        }
    }

    pub fn text(&self) -> &str {
        &self.value
    }

    pub fn is_composing(&self) -> bool {
        self.marked.is_some()
    }

    pub fn edit_revision(&self) -> u64 {
        self.edit_revision
    }

    pub fn set_text(&mut self, value: impl Into<String>, cx: &mut Context<Self>) {
        self.edit_revision = self.edit_revision.wrapping_add(1);
        self.value = single_line(&value.into());
        self.cursor = self.value.len();
        self.anchor = self.cursor;
        self.marked = None;
        self.dragging = false;
        self.scroll_x = px(0.);
        self.layout = None;
        cx.notify();
    }

    pub fn focus_handle(&self) -> FocusHandle {
        self.focus.clone()
    }

    fn selection(&self) -> Range<usize> {
        ordered_range(self.anchor, self.cursor)
    }

    fn move_to(&mut self, offset: usize, extend: bool, cx: &mut Context<Self>) {
        self.cursor = floor_boundary(&self.value, offset);
        if !extend {
            self.anchor = self.cursor;
        }
        self.marked = None;
        cx.notify();
    }

    fn horizontal(&mut self, right: bool, extend: bool, cx: &mut Context<Self>) {
        let selection = self.selection();
        let target = if !extend && !selection.is_empty() {
            if right {
                selection.end
            } else {
                selection.start
            }
        } else if right {
            next_boundary(&self.value, self.cursor)
        } else {
            previous_boundary(&self.value, self.cursor)
        };
        self.move_to(target, extend, cx);
    }

    fn replacement_range(&self, utf16: Option<Range<usize>>) -> Range<usize> {
        utf16
            .map(|range| range_from_utf16(&self.value, range))
            .or_else(|| self.marked.clone())
            .unwrap_or_else(|| self.selection())
    }

    fn replace(&mut self, range: Range<usize>, text: &str, cx: &mut Context<Self>) {
        self.edit_revision = self.edit_revision.wrapping_add(1);
        self.value.replace_range(range.clone(), text);
        self.cursor = range.start + text.len();
        self.anchor = self.cursor;
        self.marked = None;
        self.layout = None;
        cx.notify();
    }

    fn delete(&mut self, forward: bool, to_start: bool, cx: &mut Context<Self>) {
        let mut range = self.selection();
        if range.is_empty() {
            range = if to_start {
                0..self.cursor
            } else if forward {
                self.cursor..next_boundary(&self.value, self.cursor)
            } else {
                previous_boundary(&self.value, self.cursor)..self.cursor
            };
        }
        self.replace(range, "", cx);
    }

    fn copy(&self, cx: &mut Context<Self>) {
        let range = self.selection();
        // Do not export secrets, including during IME composition.
        if !self.masked && !range.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(self.value[range].to_owned()));
        }
    }

    fn cut(&mut self, cx: &mut Context<Self>) {
        if self.masked {
            return;
        }
        self.copy(cx);
        self.replace(self.selection(), "", cx);
    }

    fn paste(&mut self, cx: &mut Context<Self>) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            let text = single_line(&text);
            self.replace(self.replacement_range(None), &text, cx);
        }
    }

    fn display_text(&self) -> String {
        if self.masked {
            MASK.repeat(self.value.chars().count())
        } else {
            self.value.clone()
        }
    }

    fn display_offset(&self, offset: usize) -> usize {
        if self.masked {
            self.value[..floor_boundary(&self.value, offset)]
                .chars()
                .count()
                * MASK.len()
        } else {
            floor_boundary(&self.value, offset)
        }
    }

    fn offset_for_position(&self, position: Point<Pixels>) -> Option<usize> {
        let layout = self.layout.as_ref()?;
        if self.value.is_empty() {
            return Some(0);
        }
        let display = layout
            .line
            .closest_index_for_x(position.x - layout.origin.x);
        Some(if self.masked {
            byte_offset_for_char(&self.value, display / MASK.len())
        } else {
            floor_boundary(&self.value, display)
        })
    }
}

impl Focusable for TextInput {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.focus_handle()
    }
}

impl EntityInputHandler for TextInput {
    fn text_for_range(
        &mut self,
        range: Range<usize>,
        actual_range: &mut Option<Range<usize>>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<String> {
        platform_text_for_range(
            &self.value,
            self.masked,
            self.marked.as_ref(),
            range,
            actual_range,
        )
    }

    fn selected_text_range(
        &mut self,
        _: bool,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        Some(UTF16Selection {
            range: range_to_utf16(&self.value, self.selection()),
            reversed: self.cursor < self.anchor,
        })
    }

    fn marked_text_range(&self, _: &mut Window, _: &mut Context<Self>) -> Option<Range<usize>> {
        self.marked
            .clone()
            .map(|range| range_to_utf16(&self.value, range))
    }

    fn unmark_text(&mut self, _: &mut Window, cx: &mut Context<Self>) {
        self.marked = None;
        cx.notify();
    }

    fn replace_text_in_range(
        &mut self,
        range: Option<Range<usize>>,
        text: &str,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = self.replacement_range(range);
        self.replace(range, &single_line(text), cx);
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range: Option<Range<usize>>,
        text: &str,
        selected: Option<Range<usize>>,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = self.replacement_range(range);
        let start = range.start;
        let text = single_line(text);
        self.replace(range, &text, cx);
        if !text.is_empty() {
            self.marked = Some(start..start + text.len());
        }
        if let Some(selected) = selected {
            // The IME's selection is relative to the replacement, in UTF-16.
            let selected = range_from_utf16(&text, selected);
            self.anchor = start + selected.start;
            self.cursor = start + selected.end;
        }
    }

    fn bounds_for_range(
        &mut self,
        range: Range<usize>,
        element_bounds: Bounds<Pixels>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        // A platform may ask synchronously after an edit, before prepaint has
        // rebuilt the line. Keep its candidate window attached to the field.
        let Some(layout) = self.layout.as_ref() else {
            return Some(Bounds::new(
                element_bounds.origin,
                size(px(1.), element_bounds.size.height),
            ));
        };
        let range = range_from_utf16(&self.value, range);
        let x = |offset| {
            let x = if self.value.is_empty() {
                px(0.)
            } else {
                layout.line.x_for_index(self.display_offset(offset))
            };
            (layout.origin.x + x)
                .max(layout.bounds.left())
                .min(layout.bounds.right())
        };
        let start = x(range.start);
        let end = x(range.end);
        Some(Bounds::new(
            point(start, layout.bounds.top()),
            size((end - start).max(px(1.)), layout.bounds.size.height),
        ))
    }

    fn character_index_for_point(
        &mut self,
        position: Point<Pixels>,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<usize> {
        let layout = self.layout.as_ref()?;
        if !layout.bounds.contains(&position) {
            return None;
        }
        self.offset_for_position(position)
            .map(|offset| offset_to_utf16(&self.value, offset))
    }

    fn set_selected_text_range(
        &mut self,
        range: Range<usize>,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_from_utf16(&self.value, range);
        self.anchor = range.start;
        self.cursor = range.end;
        cx.notify();
    }

    fn text_length_utf16(&mut self, _: &mut Window, _: &mut Context<Self>) -> Option<usize> {
        Some(self.value.encode_utf16().count())
    }

    fn text_input_editable_range(
        &mut self,
        _: &mut Window,
        _: &mut Context<Self>,
    ) -> Option<Range<usize>> {
        if !self.masked {
            return None;
        }
        // Bound surrounding-text queries without rebasing document offsets.
        // text_for_range is the final guard even when a platform ignores this.
        let selection = self.selection();
        let range = match self.marked.as_ref() {
            Some(marked) if selection.start >= marked.start && selection.end <= marked.end => {
                marked.clone()
            }
            _ => selection,
        };
        Some(range_to_utf16(&self.value, range))
    }
}

impl Render for TextInput {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("text-input")
            .key_context("TextInput")
            .track_focus(&self.focus)
            .cursor(CursorStyle::IBeam)
            .w_full()
            .min_w(px(0.))
            .h(px(34.))
            .px(px(8.))
            .rounded(px(5.))
            .bg(rgb(0x232529))
            .border_1()
            .border_color(rgb(if self.focus.is_focused(window) {
                0x4f9dff
            } else {
                0x34363c
            }))
            .font_family(".SystemUIFont")
            .text_size(px(14.))
            .line_height(px(20.))
            .text_color(rgb(0xe8e9ec))
            .overflow_hidden()
            .flex()
            .items_center()
            .on_action(cx.listener(|this, _: &Left, _, cx| this.horizontal(false, false, cx)))
            .on_action(cx.listener(|this, _: &Right, _, cx| this.horizontal(true, false, cx)))
            .on_action(cx.listener(|this, _: &SelectLeft, _, cx| this.horizontal(false, true, cx)))
            .on_action(cx.listener(|this, _: &SelectRight, _, cx| this.horizontal(true, true, cx)))
            .on_action(cx.listener(|this, _: &Home, _, cx| this.move_to(0, false, cx)))
            .on_action(
                cx.listener(|this, _: &End, _, cx| this.move_to(this.value.len(), false, cx)),
            )
            .on_action(cx.listener(|this, _: &SelectHome, _, cx| this.move_to(0, true, cx)))
            .on_action(
                cx.listener(|this, _: &SelectEnd, _, cx| this.move_to(this.value.len(), true, cx)),
            )
            .on_action(cx.listener(|this, _: &Backspace, _, cx| this.delete(false, false, cx)))
            .on_action(cx.listener(|this, _: &Delete, _, cx| this.delete(true, false, cx)))
            .on_action(cx.listener(|this, _: &DeleteToStart, _, cx| this.delete(false, true, cx)))
            .on_action(cx.listener(|this, _: &SelectAll, _, cx| {
                this.anchor = 0;
                this.cursor = this.value.len();
                this.marked = None;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &Copy, _, cx| this.copy(cx)))
            .on_action(cx.listener(|this, _: &Cut, _, cx| this.cut(cx)))
            .on_action(cx.listener(|this, _: &Paste, _, cx| this.paste(cx)))
            .on_mouse_down(
                gpui::MouseButton::Left,
                cx.listener(|this, event: &gpui::MouseDownEvent, window, cx| {
                    this.focus.focus(window, cx);
                    if event.click_count >= 2 {
                        this.anchor = 0;
                        this.cursor = this.value.len();
                        this.marked = None;
                        cx.notify();
                    } else if let Some(offset) = this.offset_for_position(event.position) {
                        this.move_to(offset, event.modifiers.shift, cx);
                    }
                    this.dragging = true;
                    cx.stop_propagation();
                }),
            )
            .on_mouse_move_all({
                let input = cx.entity().downgrade();
                move |event: &gpui::MouseMoveEvent, phase, _, window, cx| {
                    if phase != DispatchPhase::Bubble {
                        return;
                    }
                    let _ = input.update(cx, |this, cx| {
                        if this.dragging && this.focus.is_focused(window) && event.dragging() {
                            if let Some(offset) = this.offset_for_position(event.position) {
                                this.move_to(offset, true, cx);
                            }
                        } else {
                            this.dragging = false;
                        }
                    });
                }
            })
            .on_mouse_up(
                gpui::MouseButton::Left,
                cx.listener(|this, _, _, _| this.dragging = false),
            )
            .on_mouse_up_out(
                gpui::MouseButton::Left,
                cx.listener(|this, _, _, _| this.dragging = false),
            )
            .child(InputText { input: cx.entity() })
    }
}

struct InputText {
    input: Entity<TextInput>,
}

struct InputPrepaint {
    selection: Option<PaintQuad>,
    marked: Option<PaintQuad>,
    cursor: Option<PaintQuad>,
}

impl IntoElement for InputText {
    type Element = Self;

    fn into_element(self) -> Self {
        self
    }
}

impl Element for InputText {
    type RequestLayoutState = ();
    type PrepaintState = InputPrepaint;

    fn id(&self) -> Option<gpui::ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _: Option<&gpui::GlobalElementId>,
        _: Option<&gpui::InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, ()) {
        let mut style = gpui::Style::default();
        style.size.width = relative(1.).into();
        style.size.height = window.line_height().into();
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _: Option<&gpui::GlobalElementId>,
        _: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _: &mut (),
        window: &mut Window,
        cx: &mut App,
    ) -> InputPrepaint {
        self.input.update(cx, |input, _| {
            let style = window.text_style();
            let placeholder = input.value.is_empty();
            // Never hand the password to the shaping system or scene.
            let text: SharedString = if placeholder {
                input.placeholder.clone()
            } else {
                input.display_text()
            }
            .into();
            let run = TextRun {
                len: text.len(),
                font: style.font(),
                color: if placeholder {
                    rgb_to_hsla(rgb(0x8d919a))
                } else {
                    style.color
                },
                background_color: None,
                underline: None,
                strikethrough: None,
                letter_spacing: style.letter_spacing,
            };
            let line = window.text_system().shape_line(
                text,
                style.font_size.to_pixels(window.rem_size()),
                &[run],
                None,
            );
            let cursor_x = if placeholder {
                px(0.)
            } else {
                line.x_for_index(input.display_offset(input.cursor))
            };
            let visible_width = (bounds.size.width - px(2.)).max(px(0.));
            let max_scroll = if placeholder {
                px(0.)
            } else {
                (line.width - visible_width).max(px(0.))
            };
            input.scroll_x = input.scroll_x.min(max_scroll).max(px(0.));
            if cursor_x < input.scroll_x {
                input.scroll_x = cursor_x;
            } else if cursor_x > input.scroll_x + visible_width {
                input.scroll_x = (cursor_x - visible_width).min(max_scroll);
            }
            let origin = point(bounds.left() - input.scroll_x, bounds.top());
            let x = |offset| origin.x + line.x_for_index(input.display_offset(offset));
            let focused = input.focus.is_focused(window);
            let selected = input.selection();
            let selection = if focused && !selected.is_empty() {
                Some(fill(
                    Bounds::new(
                        point(x(selected.start), bounds.top()),
                        size(
                            (x(selected.end) - x(selected.start)).max(px(0.)),
                            bounds.size.height,
                        ),
                    ),
                    rgba(0x4f9dff55),
                ))
            } else {
                None
            };
            let marked = input.marked.as_ref().map(|marked| {
                fill(
                    Bounds::new(
                        point(x(marked.start), bounds.bottom() - px(1.)),
                        size((x(marked.end) - x(marked.start)).max(px(1.)), px(1.)),
                    ),
                    rgb(0x4f9dff),
                )
            });
            let cursor = focused.then(|| {
                fill(
                    Bounds::new(
                        point(origin.x + cursor_x, bounds.top()),
                        size(px(1.5), bounds.size.height),
                    ),
                    rgb(0xe8e9ec),
                )
            });
            input.layout = Some(InputLayout {
                line,
                bounds,
                origin,
            });
            InputPrepaint {
                selection,
                marked,
                cursor,
            }
        })
    }

    fn paint(
        &mut self,
        _: Option<&gpui::GlobalElementId>,
        _: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _: &mut (),
        prepaint: &mut InputPrepaint,
        window: &mut Window,
        cx: &mut App,
    ) {
        // Release entity borrows before any operation taking &mut App.
        let (focus, layout) = {
            let input = self.input.read(cx);
            (input.focus.clone(), input.layout.clone())
        };
        window.handle_input(
            &focus,
            ElementInputHandler::new(bounds, self.input.clone()),
            cx,
        );
        window.with_content_mask(Some(ContentMask { bounds }), |window| {
            if let Some(selection) = prepaint.selection.take() {
                window.paint_quad(selection);
            }
            if let Some(layout) = layout.as_ref() {
                let _ = layout.line.paint(
                    layout.origin,
                    bounds.size.height,
                    TextAlign::Left,
                    None,
                    window,
                    cx,
                );
            }
            if let Some(marked) = prepaint.marked.take() {
                window.paint_quad(marked);
            }
            if let Some(cursor) = prepaint.cursor.take() {
                window.paint_quad(cursor);
            }
        });
    }
}

fn platform_text_for_range(
    value: &str,
    masked: bool,
    marked: Option<&Range<usize>>,
    requested_utf16: Range<usize>,
    actual_range: &mut Option<Range<usize>>,
) -> Option<String> {
    // Never leave stale adjusted coordinates behind when refusing a query.
    *actual_range = None;
    let range = range_from_utf16(value, requested_utf16);
    if masked {
        // Only text supplied by the IME in its current composing session can
        // be read back. Committed secrets, full-document queries and ranges
        // crossing either edge of the marked span are never exported.
        let marked = marked?;
        if marked.is_empty() || range.start < marked.start || range.end > marked.end {
            return None;
        }
    }
    *actual_range = Some(range_to_utf16(value, range.clone()));
    Some(value[range].to_owned())
}

// Editing deliberately uses Unicode scalar boundaries without adding a dependency.
// Surrogate pairs and all UTF-8 code points remain indivisible; grapheme-cluster
// navigation (e.g. an entire ZWJ emoji) is not provided by this small component.
fn floor_boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

fn previous_boundary(text: &str, offset: usize) -> usize {
    text[..floor_boundary(text, offset)]
        .char_indices()
        .next_back()
        .map_or(0, |(i, _)| i)
}

fn next_boundary(text: &str, offset: usize) -> usize {
    let offset = floor_boundary(text, offset);
    text[offset..]
        .chars()
        .next()
        .map_or(text.len(), |ch| offset + ch.len_utf8())
}

fn offset_to_utf16(text: &str, offset: usize) -> usize {
    text[..floor_boundary(text, offset)].encode_utf16().count()
}

fn offset_from_utf16(text: &str, offset: usize, round_up: bool) -> usize {
    let mut count = 0;
    for (index, ch) in text.char_indices() {
        if count == offset {
            return index;
        }
        let end = count + ch.len_utf16();
        if offset < end {
            return if round_up {
                index + ch.len_utf8()
            } else {
                index
            };
        }
        count = end;
    }
    text.len()
}

fn ordered_range(a: usize, b: usize) -> Range<usize> {
    a.min(b)..a.max(b)
}

fn range_from_utf16(text: &str, range: Range<usize>) -> Range<usize> {
    let range = ordered_range(range.start, range.end);
    let start = offset_from_utf16(text, range.start, false);
    let end = if range.is_empty() {
        start
    } else {
        offset_from_utf16(text, range.end, true)
    };
    start..end
}

fn range_to_utf16(text: &str, range: Range<usize>) -> Range<usize> {
    offset_to_utf16(text, range.start)..offset_to_utf16(text, range.end)
}

fn byte_offset_for_char(text: &str, index: usize) -> usize {
    text.char_indices()
        .nth(index)
        .map_or(text.len(), |(offset, _)| offset)
}

fn single_line(text: &str) -> String {
    // Replacing rather than deleting keeps IME-relative offsets stable (CRLF
    // occupies two UTF-16 units both before and after normalization).
    text.chars()
        .map(|ch| match ch {
            '\r' | '\n' | '\t' | '\u{2028}' | '\u{2029}' => ' ',
            _ => ch,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "snapshot")]
    #[gpui::test]
    fn edit_revision_tracks_set_replace_and_ime(cx: &mut gpui::TestAppContext) {
        let window = cx.open_window(gpui::size(px(500.), px(200.)), |_, cx| {
            TextInput::new("same", "", false, cx)
        });
        let input = window.root(cx).unwrap();
        let mut visual = gpui::VisualTestContext::from_window(window.into(), cx);
        visual.update(|window, cx| {
            input.update(cx, |input, cx| {
                assert_eq!(input.edit_revision(), 0);
                assert!(!input.is_composing());
                input.set_text("changed", cx);
                input.set_text("same", cx);
                assert_eq!(
                    input.edit_revision(),
                    2,
                    "editing back to identical text is still a new revision"
                );
                input.replace_text_in_range(Some(0..4), "same", window, cx);
                assert_eq!(input.edit_revision(), 3);
                input.replace_and_mark_text_in_range(Some(0..4), "same", None, window, cx);
                assert!(input.is_composing());
                assert_eq!(input.edit_revision(), 4);
                input.unmark_text(window, cx);
                assert!(!input.is_composing());
                input.replace_and_mark_text_in_range(None, "中文", None, window, cx);
                assert_eq!(input.edit_revision(), 5);
                input.replace_text_in_range(None, "中文", window, cx);
                assert!(!input.is_composing());
                assert_eq!(input.edit_revision(), 6);
            });
        });
    }

    #[test]
    fn utf16_round_trips_at_every_scalar_boundary() {
        for text in ["", "abc", "中文输入", "a😀中𐐀z", "e\u{301}👩\u{200d}💻"] {
            for byte in text.char_indices().map(|(i, _)| i).chain([text.len()]) {
                let utf16 = offset_to_utf16(text, byte);
                assert_eq!(offset_from_utf16(text, utf16, false), byte);
                assert_eq!(offset_from_utf16(text, utf16, true), byte);
                assert_eq!(range_from_utf16(text, utf16..utf16), byte..byte);
            }
        }
    }

    #[test]
    fn surrogate_and_out_of_bounds_ranges_are_safe() {
        let text = "a😀中";
        assert_eq!(range_from_utf16(text, 2..2), 1..1);
        assert_eq!(range_from_utf16(text, 2..3), 1..5);
        assert_eq!(range_from_utf16(text, 1..2), 1..5);
        assert_eq!(range_from_utf16(text, 3..1), 1..5);
        assert_eq!(range_from_utf16(text, 0..usize::MAX), 0..text.len());
        assert_eq!(
            range_from_utf16(text, usize::MAX..usize::MAX),
            text.len()..text.len()
        );
        assert_eq!(range_to_utf16(text, 1..5), 1..3);
        assert_eq!(offset_to_utf16(text, 3), 1);
    }

    #[test]
    fn unicode_selection_and_deletion() {
        let mut text = "a中😀z".to_owned();
        let selected = ordered_range(8, 1);
        assert_eq!(&text[selected.clone()], "中😀");
        text.replace_range(selected, "文");
        assert_eq!(text, "a文z");
        assert_eq!(previous_boundary(&text, 4), 1);
        assert_eq!(next_boundary(&text, 1), 4);
        assert_eq!(previous_boundary(&text, 0), 0);
        assert_eq!(next_boundary(&text, text.len()), text.len());
    }

    #[test]
    fn masked_positions_map_to_original_utf8() {
        let text = "中😀a";
        assert_eq!(MASK.repeat(text.chars().count()), "•••");
        assert_eq!(byte_offset_for_char(text, 0), 0);
        assert_eq!(byte_offset_for_char(text, 1), 3);
        assert_eq!(byte_offset_for_char(text, 2), 7);
        assert_eq!(byte_offset_for_char(text, 3), 8);
        assert_eq!(byte_offset_for_char(text, usize::MAX), 8);
    }

    #[test]
    fn masked_platform_queries_never_export_committed_secrets() {
        let value = "sk-private-😀key";
        for range in [0..usize::MAX, 0..2, 3..7, 0..0, usize::MAX..usize::MAX] {
            let mut actual = Some(42..43);
            assert_eq!(
                platform_text_for_range(value, true, None, range, &mut actual),
                None
            );
            assert_eq!(actual, None);
        }
    }

    #[test]
    fn masked_platform_queries_only_export_current_marked_span() {
        let value = "sk-private中😀suffix-secret";
        let marked = 10..17;
        let mut actual = None;
        assert_eq!(
            platform_text_for_range(value, true, Some(&marked), 10..13, &mut actual),
            Some("中😀".to_owned()),
        );
        assert_eq!(actual, Some(10..13));
        for range in [0..usize::MAX, 0..10, 9..11, 12..14, 13..15] {
            assert_eq!(
                platform_text_for_range(value, true, Some(&marked), range, &mut actual),
                None
            );
            assert_eq!(actual, None);
        }
        // Unmarking/committing immediately makes even the former span unreadable.
        assert_eq!(
            platform_text_for_range(value, true, None, 10..13, &mut actual),
            None
        );
    }

    #[test]
    fn ordinary_platform_queries_keep_document_utf16_coordinates() {
        let value = "a中😀z";
        let mut actual = None;
        assert_eq!(
            platform_text_for_range(value, false, None, 1..4, &mut actual),
            Some("中😀".to_owned())
        );
        assert_eq!(actual, Some(1..4));
        assert_eq!(range_from_utf16(value, actual.unwrap()), 1..8);
        // A Unicode secret selection still uses the real document's units,
        // not the number of bullets or bytes in its masked display.
        assert_eq!(range_to_utf16(value, ordered_range(8, 1)), 1..4);
    }

    #[test]
    fn single_line_preserves_ime_utf16_offsets() {
        let original = "中\r\n😀\t\u{2028}\u{2029}";
        let normalized = single_line(original);
        assert_eq!(normalized, "中  😀   ");
        assert_eq!(
            original.encode_utf16().count(),
            normalized.encode_utf16().count()
        );
    }
}
