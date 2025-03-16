#[derive(Debug)]
pub enum Consistency {
    QUORUM,
    ONE,
    ALL,
}
