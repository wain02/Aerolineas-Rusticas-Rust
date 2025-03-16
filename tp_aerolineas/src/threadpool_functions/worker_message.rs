pub type Job = Box<dyn FnOnce() + Send + 'static>;

pub enum WorkerMessage {
    Job(Job),
    Terminate,
}
