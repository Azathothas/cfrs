//! A line diff with no dependency: the longest common subsequence of the
//! lines of two texts, after their common head and tail are set aside. It
//! gives each unchanged old line its new number; `remap` moves citations by
//! it.

/// Above this many cells (old lines times new lines, after the common head
/// and tail), the middle is not aligned and counts as changed: the table
/// would need more than 64 MiB.
const MAX_CELLS: usize = 16 * 1024 * 1024;

/// For each line of `old` (index 0 is line 1), its line number in `new`, or
/// `None` when the edit removed or changed it.
pub fn line_map(old: &[&str], new: &[&str]) -> Vec<Option<usize>> {
    let (n, m) = (old.len(), new.len());
    let mut map = vec![None; n];
    let mut head = 0;
    while head < n && head < m && old[head] == new[head] {
        map[head] = Some(head + 1);
        head += 1;
    }
    let mut tail = 0;
    while tail < n - head && tail < m - head && old[n - 1 - tail] == new[m - 1 - tail] {
        map[n - 1 - tail] = Some(m - tail);
        tail += 1;
    }
    let a = &old[head..n - tail];
    let b = &new[head..m - tail];
    if a.is_empty() || b.is_empty() || a.len().saturating_mul(b.len()) > MAX_CELLS {
        slide_up(&mut map, new);
        return map;
    }
    // lcs[i * w + j] is the length of a longest common subsequence of a[i..]
    // and b[j..].
    let w = b.len() + 1;
    let mut lcs = vec![0u32; (a.len() + 1) * w];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i * w + j] =
                if a[i] == b[j] { lcs[(i + 1) * w + j + 1] + 1 } else { lcs[(i + 1) * w + j].max(lcs[i * w + j + 1]) };
        }
    }
    // Two equal lines can always be matched: some longest subsequence does.
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            map[head + i] = Some(head + j + 1);
            i += 1;
            j += 1;
        } else if lcs[(i + 1) * w + j] >= lcs[i * w + j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    slide_up(&mut map, new);
    map
}

/// Each unchanged line at the earliest place where the same text allows it.
/// The common tail is matched from the end, so new functions added after
/// the closing `}` of a cited one would take that `}` as theirs; when the
/// first added line has the same text as the line after the addition, the
/// addition can be read as coming after it, and the citation keeps its own
/// lines.
fn slide_up(map: &mut [Option<usize>], new: &[&str]) {
    let mut before = 0;
    for slot in map.iter_mut() {
        if let Some(at) = *slot {
            if at > before + 1 && new[before] == new[at - 1] {
                *slot = Some(before + 1);
            }
            before = slot.unwrap_or(at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(old: &str, new: &str) -> Vec<Option<usize>> {
        let o: Vec<&str> = old.lines().collect();
        let n: Vec<&str> = new.lines().collect();
        line_map(&o, &n)
    }

    #[test]
    fn an_unchanged_text_maps_to_itself() {
        assert_eq!(map("a\nb\nc\n", "a\nb\nc\n"), vec![Some(1), Some(2), Some(3)]);
        assert_eq!(map("", ""), Vec::<Option<usize>>::new());
    }

    #[test]
    fn a_line_added_above_moves_each_line_below() {
        assert_eq!(map("a\nb\nc\n", "new\na\nb\nc\n"), vec![Some(2), Some(3), Some(4)]);
        assert_eq!(map("a\nb\nc\n", "a\nnew\nnew\nb\nc\n"), vec![Some(1), Some(4), Some(5)]);
    }

    #[test]
    fn a_changed_or_removed_line_has_no_new_number() {
        assert_eq!(map("a\nb\nc\n", "a\nB\nc\n"), vec![Some(1), None, Some(3)]);
        assert_eq!(map("a\nb\nc\nd\n", "a\nd\n"), vec![Some(1), None, None, Some(2)]);
    }

    /// New code after a closing line, with a change above it: the old
    /// closing line stays with its own part, not with the new code.
    #[test]
    fn an_addition_after_a_closing_line_comes_after_it() {
        let old = "top\nfn a {\nx\n}\n}\n";
        let new = "TOP\nfn a {\nx\n}\nfn b {\ny\n}\n}\n";
        assert_eq!(map(old, new), vec![None, Some(2), Some(3), Some(4), Some(8)]);
    }

    #[test]
    fn the_middle_is_aligned_around_a_change() {
        let old = "h\nx\n1\n2\n3\ny\nt\n";
        let new = "h\nX\n0\n1\n2\n3\nY\nt\n";
        assert_eq!(map(old, new), vec![Some(1), None, Some(4), Some(5), Some(6), None, Some(8)]);
    }
}
