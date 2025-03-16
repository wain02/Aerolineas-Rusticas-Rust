use super::{worker::Worker, worker_message::WorkerMessage};
use std::io::ErrorKind;
use std::thread;
use std::{
    io::Error,
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, Mutex,
    },
};

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Sender<WorkerMessage>,
}

impl ThreadPool {
    pub fn new(size: usize) -> Result<ThreadPool, Error> {
        if size == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "ThreadPool size cannot be zero.",
            ));
        }

        let (sender, receiver): (Sender<WorkerMessage>, Receiver<WorkerMessage>) = mpsc::channel();

        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id, Arc::clone(&receiver)));
        }
        Ok(ThreadPool { workers, sender })
    }

    pub fn execute<F>(&self, f: F) -> Result<(), Error>
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);
        self.sender
            .send(WorkerMessage::Job(job))
            .map_err(|_| Error::new(ErrorKind::Other, "Failed to send job to worker."))
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        for worker in &self.workers {
            if let Err(e) = self.sender.send(WorkerMessage::Terminate) {
                eprintln!(
                    "Error sending terminate message to worker {} due to: {:?}",
                    worker.id, e
                );
            }
        }

        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                if let Err(e) = thread.join() {
                    eprintln!("Error joining worker {} thread due to: {:?}", worker.id, e);
                }
            }
        }
    }
}

pub fn initialize_thread_pool() -> Result<ThreadPool, std::io::Error> {
    let pool_size = match thread::available_parallelism() {
        Ok(_) => 20,
        Err(_) => 23, //ver de cambiar
    };

    let pool = ThreadPool::new(pool_size)?;

    Ok(pool)
}
