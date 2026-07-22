use std::io;

/// Runtime result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the runtime.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Runtime configuration was invalid.
    #[error("invalid runtime configuration: {0}")]
    Configuration(String),
    /// The component could not be read.
    #[error("component I/O failed: {0}")]
    Io(String),
    /// The component failed compilation or deserialization.
    #[error("component preparation failed: {0}")]
    Preparation(String),
    /// The component does not implement a supported standard command world.
    #[error("unsupported component: {0}")]
    UnsupportedComponent(String),
    /// Component instantiation or execution failed.
    #[error("component execution failed: {0}")]
    Execution(String),
    /// A configured resource limit was exceeded.
    #[error("runtime limit exceeded: {0}")]
    Limit(&'static str),
    /// Execution was cancelled.
    #[error("component execution was cancelled")]
    Cancelled,
    /// A paused invocation exceeded its configured resident lifetime.
    #[error("paused invocation was evicted after its resident lifetime expired")]
    IdleEvicted,
    /// An operation was not valid for the invocation's current lifecycle state.
    #[error("invalid invocation state: {0}")]
    InvalidState(&'static str),
    /// Execution exceeded its wall-clock deadline.
    #[error("component execution timed out")]
    Timeout,
    /// Authenticated cache state was invalid and could not be recovered.
    #[error("AOT cache failed: {0}")]
    Cache(String),
    /// A WASIX checkpoint artifact was invalid or incompatible.
    #[error("WASIX checkpoint failed: {0}")]
    Checkpoint(String),
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
