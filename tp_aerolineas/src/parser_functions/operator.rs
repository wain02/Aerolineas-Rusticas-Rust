// Operadores posibles para las condiciones
#[derive(Debug, PartialEq)]
pub enum Operator {
    Equal,              // "="
    NotEqual,           // "!="
    GreaterThan,        // ">"
    LessThan,           // "<"
    GreaterThanOrEqual, // ">="
    LessThanOrEqual,    // "<="
    And,                // "AND"
    Or,                 // "OR"
    Not,                // "NOT"
}
