//! Pure-logic helpers for the framebuffer viewport / scrollback paging.
//!
//! Lives outside `framebuffer.rs` so it compiles under host `cargo test`
//! (the framebuffer module itself depends on raw-pointer pixel writes
//! that are kernel-target only).

/// Saturating clamp used by `Console::scroll_view_up`. Stepping past
/// `scroll_filled` is silently capped so a held key doesn't wrap.
pub fn clamp_offset_up(offset: usize, step: usize, filled: usize) -> usize {
    offset.saturating_add(step).min(filled)
}

/// Saturating clamp used by `Console::scroll_view_down`. Returns 0 when
/// the step would underflow.
pub fn clamp_offset_down(offset: usize, step: usize) -> usize {
    offset.saturating_sub(step)
}

/// Number of viewport rows that come from the scrollback ring vs. the
/// live cell grid for a given offset/filled/rows configuration.
/// Returns `(scrollback_rows, live_rows)`. The two always sum to `rows`.
pub fn split_viewport(offset: usize, filled: usize, rows: usize) -> (usize, usize) {
    let k = offset.min(filled).min(rows);
    (k, rows - k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_viewport_pinned_at_bottom_is_all_live() {
        let (sb, live) = split_viewport(0, 200, 30);
        assert_eq!((sb, live), (0, 30));
    }

    #[test]
    fn split_viewport_partial_scrollback() {
        let (sb, live) = split_viewport(5, 200, 30);
        assert_eq!((sb, live), (5, 25));
    }

    #[test]
    fn split_viewport_offset_clamped_by_filled() {
        let (sb, live) = split_viewport(50, 8, 30);
        assert_eq!((sb, live), (8, 22));
    }

    #[test]
    fn split_viewport_offset_clamped_by_rows() {
        let (sb, live) = split_viewport(100, 200, 30);
        assert_eq!((sb, live), (30, 0));
    }

    #[test]
    fn clamp_offset_up_saturates_at_filled() {
        assert_eq!(clamp_offset_up(0, 29, 200), 29);
        assert_eq!(clamp_offset_up(190, 29, 200), 200);
        assert_eq!(clamp_offset_up(usize::MAX - 1, 29, 200), 200);
    }

    #[test]
    fn clamp_offset_up_no_history_stays_zero() {
        assert_eq!(clamp_offset_up(0, 29, 0), 0);
    }

    #[test]
    fn clamp_offset_down_saturates_at_zero() {
        assert_eq!(clamp_offset_down(29, 29), 0);
        assert_eq!(clamp_offset_down(10, 29), 0);
        assert_eq!(clamp_offset_down(50, 29), 21);
    }

    #[test]
    fn page_paging_is_reversible() {
        let filled = 200;
        let page = 29;
        let after_up = clamp_offset_up(0, page, filled);
        let after_down = clamp_offset_down(after_up, page);
        assert_eq!(after_down, 0);
    }
}
