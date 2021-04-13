use std::ops::{Index, IndexMut};

pub struct Matrix<T> {
    _rows: usize,
    cols: usize,
    entries: Vec<T>,
}

#[allow(dead_code)]
impl<T: Default> Matrix<T> {
    pub fn new(rows: usize, cols: usize) -> Matrix<T> {
        let mut entries = Vec::new();
        entries.resize_with(rows * cols, Default::default);
        Matrix {
            _rows: rows,
            cols,
            entries,
        }
    }
}

#[allow(dead_code)]
impl<T> Index<(usize, usize)> for Matrix<T> {
    type Output = T;
    fn index(&self, index: (usize, usize)) -> &T {
        &self.entries[self.cols * index.0 + index.1]
    }
}

#[allow(dead_code)]
impl<T> IndexMut<(usize, usize)> for Matrix<T> {
    fn index_mut(&mut self, index: (usize, usize)) -> &mut T {
        &mut self.entries[self.cols * index.0 + index.1]
    }
}

#[allow(dead_code)]
impl<T> Matrix<T> {
    pub fn row_major_entries(&self) -> impl Iterator<Item = &T> {
        self.entries.iter()
    }
}
