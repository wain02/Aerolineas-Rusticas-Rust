use super::worker_message::WorkerMessage;
use std::{
    sync::{
        mpsc::{Receiver, RecvTimeoutError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub struct Worker {
    pub id: usize,
    pub thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub fn new(id: usize, receiver: Arc<Mutex<Receiver<WorkerMessage>>>) -> Worker {
        let thread = thread::Builder::new()
            .name(format!("threadpool-worker-{}", id))
            .spawn(move || loop {
                let job = match receiver.lock() {
                    Ok(guard) => match guard.recv_timeout(Duration::from_millis(100)) {
                        Ok(WorkerMessage::Job(job)) => job,
                        Ok(WorkerMessage::Terminate) => break,
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(_) => break,
                    },
                    Err(_) => break,
                };

                job();
            })
            .expect("Failed to spawn threadpool-worker");

        Worker {
            id,
            thread: Some(thread),
        }
    }
}
