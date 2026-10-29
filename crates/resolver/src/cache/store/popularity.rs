//! Exact least-popular ordering with stable slot-index tie breaking.
//! Updating a hit count reorders existing storage without tree-node churn.

pub(super) struct Popularity {
    heap: Vec<(u32, usize)>,
    positions: Vec<usize>,
}

impl Popularity {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            heap: Vec::with_capacity(capacity),
            positions: Vec::with_capacity(capacity),
        }
    }

    pub(super) fn first(&self) -> Option<&(u32, usize)> {
        self.heap.first()
    }

    pub(super) fn insert(&mut self, entry: (u32, usize)) {
        let index = entry.1;
        if self.positions.len() <= index {
            self.positions.resize(index + 1, usize::MAX);
        }
        assert_eq!(self.positions[index], usize::MAX);
        self.positions[index] = self.heap.len();
        self.heap.push(entry);
        self.sift_up(self.heap.len() - 1);
    }

    pub(super) fn update(&mut self, index: usize, hits: u32) {
        let position = self.positions[index];
        debug_assert!(hits >= self.heap[position].0);
        self.heap[position].0 = hits;
        self.sift_down(position);
    }

    pub(super) fn remove(&mut self, entry: &(u32, usize)) {
        let position = self.positions[entry.1];
        assert_eq!(self.heap[position], *entry);
        self.positions[entry.1] = usize::MAX;
        self.heap.swap_remove(position);
        if position < self.heap.len() {
            self.positions[self.heap[position].1] = position;
            if position > 0 && self.heap[position] < self.heap[(position - 1) / 2] {
                self.sift_up(position);
            } else {
                self.sift_down(position);
            }
        }
    }

    fn swap(&mut self, left: usize, right: usize) {
        self.heap.swap(left, right);
        self.positions[self.heap[left].1] = left;
        self.positions[self.heap[right].1] = right;
    }

    fn sift_up(&mut self, mut position: usize) {
        while position > 0 {
            let parent = (position - 1) / 2;
            if self.heap[parent] <= self.heap[position] {
                break;
            }
            self.swap(parent, position);
            position = parent;
        }
    }

    fn sift_down(&mut self, mut position: usize) {
        loop {
            let left = position * 2 + 1;
            if left >= self.heap.len() {
                break;
            }
            let right = left + 1;
            let child = if right < self.heap.len() && self.heap[right] < self.heap[left] {
                right
            } else {
                left
            };
            if self.heap[position] <= self.heap[child] {
                break;
            }
            self.swap(position, child);
            position = child;
        }
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.heap.len()
    }

    #[cfg(test)]
    pub(super) fn contains(&self, entry: &(u32, usize)) -> bool {
        self.positions
            .get(entry.1)
            .and_then(|&position| self.heap.get(position))
            == Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn matches_tree_order_through_hits_removal_and_slot_reuse() {
        let mut heap = Popularity::with_capacity(257);
        let mut tree = BTreeSet::new();
        let mut hits = [None; 257];
        let mut seed = 0x10356891_u64;
        for step in 0..30_000 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let index = seed as usize % hits.len();
            match hits[index] {
                Some(count) if step % 3 == 0 => {
                    heap.remove(&(count, index));
                    tree.remove(&(count, index));
                    hits[index] = None;
                }
                Some(count) => {
                    let next = count.saturating_add(1);
                    heap.update(index, next);
                    tree.remove(&(count, index));
                    tree.insert((next, index));
                    hits[index] = Some(next);
                }
                None => {
                    let count = if step % 7 == 0 { u32::MAX } else { 0 };
                    heap.insert((count, index));
                    tree.insert((count, index));
                    hits[index] = Some(count);
                }
            }
            assert_eq!(heap.first(), tree.first());
            assert_eq!(heap.len(), tree.len());
            for &(count, index) in &tree {
                assert!(heap.contains(&(count, index)));
            }
            for position in 1..heap.len() {
                assert!(heap.heap[(position - 1) / 2] <= heap.heap[position]);
            }
            assert!(heap.positions.len() <= hits.len());
        }
        while let Some(&entry) = tree.first() {
            assert_eq!(heap.first(), Some(&entry));
            heap.remove(&entry);
            tree.remove(&entry);
        }
        assert!(heap.first().is_none());
    }
}
