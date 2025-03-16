use crate::parser_functions::elemento_condicion_pila::ElementoCondicionPila;
// Condiciones compuestas que pueden incluir AND/OR
#[derive(Debug)]
pub struct CondicionCompuesta {
    pub pila_condiciones: Vec<ElementoCondicionPila>,
}
