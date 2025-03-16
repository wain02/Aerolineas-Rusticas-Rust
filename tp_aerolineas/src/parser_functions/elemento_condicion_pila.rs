use crate::parser_functions::operator::Operator;
use crate::parser_functions::simple_condition::SimpleCondition;
#[derive(Debug)]
pub enum ElementoCondicionPila {
    SimpleCondition(SimpleCondition),
    Operator(Operator),
}
