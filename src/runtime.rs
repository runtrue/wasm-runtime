use crate::{
    CancellationToken, CommandInput, CommandOutput, Error, InvocationState, PackageTier,
    PauseToken, PhaseTimings, Result, RunMeasurement, RuntimeConfig, WasiProfile,
    cache::{DiskCache, component_digest},
};
use bytes::Bytes;
use std::{
    collections::HashMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use wasmtime::{
    Config, Engine, OptLevel, Store, StoreLimits, StoreLimitsBuilder, UpdateDeadline,
    component::{Component, Linker, ResourceTable},
};
use wasmtime_wasi::{WasiCtx, WasiCtxView, WasiView};

/// Builder for a [`Runtime`].
#[derive(Debug, Default)]
pub struct RuntimeBuilder {
    config: RuntimeConfig,
}

impl RuntimeBuilder {
    /// Start with secure, bounded defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the complete runtime configuration.
    #[must_use]
    pub fn with_config(mut self, config: RuntimeConfig) -> Self {
        self.config = config;
        self
    }

    /// Construct the runtime and start its epoch watchdog.
    ///
    /// # Errors
    ///
    /// Returns an error when configuration, engine, linker, cache, or watchdog
    /// initialization fails.
    pub fn build(self) -> Result<Runtime> {
        Runtime::new(self.config)
    }
}

/// Shared WASI Component runtime and package cache.
#[derive(Clone)]
pub struct Runtime {
    pub(crate) inner: Arc<RuntimeInner>,
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Runtime").finish_non_exhaustive()
    }
}

impl Runtime {
    /// Construct a runtime from explicit configuration.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits or when the Wasmtime engine,
    /// standard linkers, disk cache, or epoch watchdog cannot be initialized.
    pub fn new(config: RuntimeConfig) -> Result<Self> {
        validate_config(&config)?;
        let engine = Engine::new(&engine_config())
            .map_err(|error| Error::Configuration(error.to_string()))?;
        let mut p3_linker = Linker::new(&engine);
        wasmtime_wasi::p3::add_to_linker(&mut p3_linker)
            .map_err(|error| Error::Configuration(error.to_string()))?;
        // Preview 3 components produced through the current preview 1 adapter
        // may still import preview 2 CLI interfaces alongside their p3 export.
        wasmtime_wasi::p2::add_to_linker_async(&mut p3_linker)
            .map_err(|error| Error::Configuration(error.to_string()))?;
        wasmtime_wasi_http::p3::add_to_linker(&mut p3_linker)
            .map_err(|error| Error::Configuration(error.to_string()))?;
        let mut p2_linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut p2_linker)
            .map_err(|error| Error::Configuration(error.to_string()))?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut p2_linker)
            .map_err(|error| Error::Configuration(error.to_string()))?;
        let target = format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS);
        let disk = config
            .disk_cache
            .clone()
            .map(|cache| DiskCache::prepare(cache, target))
            .transpose()?;
        let stop_epoch = Arc::new(AtomicBool::new(false));
        let epoch_thread = spawn_epoch_ticker(
            engine.clone(),
            config.epoch_interval,
            Arc::clone(&stop_epoch),
        )?;
        let background_workers = config.background_workers;
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                engine,
                p3_linker,
                p2_linker,
                memory: Mutex::new(MemoryCache::new(&config)),
                preparation_locks: Mutex::new(HashMap::new()),
                disk,
                background: Arc::new(Semaphore::new(background_workers)),
                stop_epoch,
                epoch_thread: Some(epoch_thread),
                config,
            }),
        })
    }

    /// Construct a runtime with bounded defaults and no disk AOT cache.
    ///
    /// # Errors
    ///
    /// Returns an error when runtime initialization fails.
    pub fn with_defaults() -> Result<Self> {
        RuntimeBuilder::new().build()
    }

    /// Load component bytes and schedule bounded background promotion when
    /// called from a Tokio runtime. The returned handle can be invoked
    /// immediately; a call joins the same per-digest preparation lock.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied component is empty.
    pub fn load_bytes(&self, bytes: impl Into<Vec<u8>>) -> Result<Program> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(Error::UnsupportedComponent(
                "component bytes are empty".to_owned(),
            ));
        }
        let program = Program {
            runtime: self.clone(),
            digest: component_digest(&bytes),
            bytes: Arc::from(bytes),
        };
        program.schedule_background_promotion();
        Ok(program)
    }

    /// Read a component from disk without granting that path to the guest.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or is empty.
    pub fn load_file(&self, path: impl AsRef<Path>) -> Result<Program> {
        self.load_bytes(std::fs::read(path)?)
    }
}

/// Loaded standard WASI command component.
#[derive(Clone)]
pub struct Program {
    pub(crate) runtime: Runtime,
    pub(crate) digest: String,
    pub(crate) bytes: Arc<[u8]>,
}

impl std::fmt::Debug for Program {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Program")
            .field("digest", &self.digest)
            .field("tier", &self.tier())
            .finish_non_exhaustive()
    }
}

impl Program {
    /// SHA-256 digest of the original component bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Best currently retained tier for this package.
    #[must_use]
    pub fn tier(&self) -> PackageTier {
        self.runtime.inner.tier(&self.digest)
    }

    /// Explicitly promote the package to the warm compiled-component tier.
    ///
    /// # Errors
    ///
    /// Returns an error when cache authentication, compilation,
    /// deserialization, or standard-profile validation fails.
    pub async fn prepare(&self) -> Result<PackageTier> {
        self.runtime
            .inner
            .prepare(&self.digest, Arc::clone(&self.bytes))
            .await?;
        Ok(PackageTier::Warm)
    }

    /// Invoke the standard command with a fresh Store, instance, WASI context,
    /// input streams, output streams, limits, fuel, timeout, and cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid limits, failed preparation, failed
    /// instantiation, a guest trap, timeout, or cancellation.
    pub async fn run(&self, input: CommandInput) -> Result<CommandOutput> {
        self.run_controlled(input, PauseToken::new()).await
    }

    /// Spawn an independently controllable invocation on the current Tokio
    /// runtime.
    ///
    /// # Errors
    ///
    /// Returns an error when called outside a Tokio runtime.
    pub fn start(&self, input: CommandInput) -> Result<RunningCommand> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| {
            Error::Configuration("Program::start requires an active Tokio runtime".to_owned())
        })?;
        let pause = PauseToken::new();
        let cancellation = input.cancellation.clone();
        let program = self.clone();
        let task_pause = pause.clone();
        let task = handle.spawn(async move {
            let output = program.run_controlled(input, task_pause.clone()).await;
            if matches!(output, Err(Error::IdleEvicted)) {
                program.runtime.inner.demote(&program.digest);
            }
            output
        });
        Ok(RunningCommand {
            pause,
            cancellation,
            task: Some(task),
        })
    }

    async fn run_controlled(
        &self,
        input: CommandInput,
        pause: PauseToken,
    ) -> Result<CommandOutput> {
        if input.stdin.len() > self.runtime.inner.config.limits.max_input_bytes {
            return Err(Error::Limit("input bytes"));
        }
        if input.timeout.is_zero() || input.timeout > self.runtime.inner.config.limits.max_timeout {
            return Err(Error::Limit("timeout"));
        }
        if input.cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let total_started = Instant::now();
        let prepared_from = self.tier();
        let prepare_started = Instant::now();
        let prepared = self
            .runtime
            .inner
            .prepare(&self.digest, Arc::clone(&self.bytes))
            .await?;
        let prepare = prepare_started.elapsed();
        if !prepared.profile.is_command() {
            return Err(Error::UnsupportedComponent(
                "HTTP components must be invoked through Program::http_service".to_owned(),
            ));
        }

        let InvocationResult {
            stdout,
            stderr,
            exit_code,
            instantiate,
            execute,
            suspended,
        } = self.runtime.inner.invoke(&prepared, input, pause).await?;

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_code,
            wasi_version: prepared.profile.version(),
            measurement: RunMeasurement {
                prepared_from,
                retained_as: PackageTier::Warm,
                wasi_version: prepared.profile.version(),
                phases: PhaseTimings {
                    prepare,
                    instantiate,
                    execute,
                    suspended,
                    active_execute: execute.saturating_sub(suspended),
                    total: total_started.elapsed(),
                },
            },
        })
    }

    fn schedule_background_promotion(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let program = self.clone();
        let semaphore = Arc::clone(&self.runtime.inner.background);
        handle.spawn(async move {
            let Ok(_permit) = semaphore.acquire_owned().await else {
                return;
            };
            let _ = program.prepare().await;
        });
    }
}

/// A live command invocation with cooperative pause, resume, and cancellation.
///
/// Pausing retains the Store and guest state until
/// [`RuntimeConfig::paused_resident_ttl`] expires. Expiry drops the invocation,
/// demotes its package cache entry when possible, and returns
/// [`Error::IdleEvicted`] from [`Self::wait`]. It never silently restarts the
/// guest.
pub struct RunningCommand {
    pause: PauseToken,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<CommandOutput>>>,
}

impl std::fmt::Debug for RunningCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunningCommand")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl RunningCommand {
    /// Request a cooperative pause while retaining the live Store and instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the invocation has already finished or was evicted.
    pub fn pause(&self) -> Result<()> {
        match self.state() {
            InvocationState::Running
            | InvocationState::PauseRequested
            | InvocationState::PausedResident => {
                self.pause.pause();
                Ok(())
            }
            InvocationState::Evicted => Err(Error::IdleEvicted),
            InvocationState::Finished => Err(Error::InvalidState("invocation already finished")),
        }
    }

    /// Resume the same resident Store and instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the invocation has already finished or its idle TTL
    /// expired. An evicted invocation must be explicitly started again.
    pub fn resume(&self) -> Result<()> {
        match self.state() {
            InvocationState::Running => Ok(()),
            InvocationState::PauseRequested | InvocationState::PausedResident
                if self.pause.resume() =>
            {
                Ok(())
            }
            InvocationState::PauseRequested
            | InvocationState::PausedResident
            | InvocationState::Evicted => Err(Error::IdleEvicted),
            InvocationState::Finished => Err(Error::InvalidState("invocation already finished")),
        }
    }

    /// Request cancellation, including while the invocation is paused.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Current observable invocation lifecycle state.
    #[must_use]
    pub fn state(&self) -> InvocationState {
        if self.pause.is_evicted() {
            InvocationState::Evicted
        } else if self
            .task
            .as_ref()
            .is_none_or(tokio::task::JoinHandle::is_finished)
        {
            InvocationState::Finished
        } else if self.pause.is_resident() {
            InvocationState::PausedResident
        } else if self.pause.is_paused() {
            InvocationState::PauseRequested
        } else {
            InvocationState::Running
        }
    }

    /// Wait for the invocation's output or terminal error.
    ///
    /// # Errors
    ///
    /// Returns the runtime error, [`Error::IdleEvicted`] after idle eviction,
    /// or an execution error if the Tokio task failed.
    pub async fn wait(mut self) -> Result<CommandOutput> {
        let task = self
            .task
            .take()
            .ok_or(Error::InvalidState("invocation result already consumed"))?;
        task.await
            .map_err(|error| Error::Execution(format!("invocation task failed: {error}")))?
    }
}

impl Drop for RunningCommand {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.cancellation.cancel();
            let _ = self.pause.resume();
        }
    }
}

pub(crate) struct RuntimeInner {
    pub(crate) engine: Engine,
    pub(crate) p3_linker: Linker<HostState>,
    pub(crate) p2_linker: Linker<HostState>,
    memory: Mutex<MemoryCache>,
    preparation_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    disk: Option<DiskCache>,
    background: Arc<Semaphore>,
    stop_epoch: Arc<AtomicBool>,
    epoch_thread: Option<thread::JoinHandle<()>>,
    pub(crate) config: RuntimeConfig,
}

impl RuntimeInner {
    pub(crate) fn demote(&self, digest: &str) {
        if let Ok(mut memory) = self.memory.lock() {
            memory.demote(digest);
        }
    }

    fn tier(&self, digest: &str) -> PackageTier {
        if let Ok(mut memory) = self.memory.lock() {
            if memory.warm(digest).is_some() {
                return PackageTier::Warm;
            }
            if memory.warmish(digest).is_some() {
                return PackageTier::Warmish;
            }
        }
        if self.disk.as_ref().is_some_and(|disk| {
            WasiProfile::ALL
                .into_iter()
                .any(|profile| disk.contains(digest, profile))
        }) {
            PackageTier::DiskAot
        } else {
            PackageTier::Cold
        }
    }

    pub(crate) async fn prepare(
        &self,
        digest: &str,
        source: Arc<[u8]>,
    ) -> Result<Arc<PreparedComponent>> {
        if let Some(component) = self
            .memory
            .lock()
            .map_err(|_| Error::Preparation("memory cache is poisoned".to_owned()))?
            .warm(digest)
        {
            return Ok(component);
        }

        let lock = self
            .preparation_locks
            .lock()
            .map_err(|_| Error::Preparation("preparation lock map is poisoned".to_owned()))?
            .entry(digest.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        if let Some(component) = self
            .memory
            .lock()
            .map_err(|_| Error::Preparation("memory cache is poisoned".to_owned()))?
            .warm(digest)
        {
            return Ok(component);
        }

        let warmish = {
            self.memory
                .lock()
                .map_err(|_| Error::Preparation("memory cache is poisoned".to_owned()))?
                .warmish(digest)
        };
        if let Some(aot) = warmish {
            let prepared = Arc::new(deserialize_component(&self.engine, &aot)?);
            self.memory
                .lock()
                .map_err(|_| Error::Preparation("memory cache is poisoned".to_owned()))?
                .insert_warm(digest.to_owned(), Arc::clone(&prepared));
            return Ok(prepared);
        }

        if let Some(disk) = &self.disk {
            for profile in WasiProfile::ALL {
                if let Some(bytes) = disk.load(digest, profile)? {
                    let aot = Arc::new(PreparedAot { bytes, profile });
                    let prepared = Arc::new(deserialize_component(&self.engine, &aot)?);
                    if prepared.profile != profile {
                        return Err(Error::Cache(
                            "serialized artifact profile does not match its identity".to_owned(),
                        ));
                    }
                    let mut memory = self
                        .memory
                        .lock()
                        .map_err(|_| Error::Preparation("memory cache is poisoned".to_owned()))?;
                    memory.insert_warmish(digest.to_owned(), &aot);
                    memory.insert_warm(digest.to_owned(), Arc::clone(&prepared));
                    return Ok(prepared);
                }
            }
        }

        let engine = self.engine.clone();
        let source_for_compile = Arc::clone(&source);
        let prepared = tokio::task::spawn_blocking(move || {
            let component = Component::from_binary(&engine, &source_for_compile)
                .map_err(|error| Error::Preparation(format!("{error:?}")))?;
            let profile = detect_profile(&engine, &component)?;
            let bytes = component
                .serialize()
                .map_err(|error| Error::Preparation(error.to_string()))?;
            Ok::<_, Error>((PreparedComponent { component, profile }, bytes))
        })
        .await
        .map_err(|error| Error::Preparation(format!("compiler task failed: {error}")))??;
        let (prepared, aot_bytes) = prepared;
        if let Some(disk) = &self.disk {
            disk.publish(digest, prepared.profile, &aot_bytes)?;
        }
        let aot = Arc::new(PreparedAot {
            bytes: aot_bytes,
            profile: prepared.profile,
        });
        let prepared = Arc::new(prepared);
        let mut memory = self
            .memory
            .lock()
            .map_err(|_| Error::Preparation("memory cache is poisoned".to_owned()))?;
        memory.insert_warmish(digest.to_owned(), &aot);
        memory.insert_warm(digest.to_owned(), Arc::clone(&prepared));
        Ok(prepared)
    }

    #[allow(clippy::too_many_lines)]
    async fn invoke(
        &self,
        prepared: &PreparedComponent,
        input: CommandInput,
        pause: PauseToken,
    ) -> Result<InvocationResult> {
        let invocation_cancellation = input.cancellation.clone();
        let stdout =
            wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(self.config.limits.max_output_bytes);
        let stderr =
            wasmtime_wasi::p2::pipe::MemoryOutputPipe::new(self.config.limits.max_output_bytes);
        let mut wasi = WasiCtx::builder();
        wasi.stdin(wasmtime_wasi::p2::pipe::MemoryInputPipe::new(Bytes::from(
            input.stdin,
        )))
        .stdout(stdout.clone())
        .stderr(stderr.clone())
        .args(&input.args)
        .allow_tcp(false)
        .allow_udp(false)
        .allow_ip_name_lookup(false);
        for (key, value) in &input.env {
            wasi.env(key, value);
        }
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.limits.max_memory_bytes)
            .table_elements(self.config.limits.max_table_elements)
            .instances(self.config.limits.max_instances)
            .tables(100)
            .memories(100)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(
            &self.engine,
            HostState {
                wasi: wasi.build(),
                http: wasmtime_wasi_http::WasiHttpCtx::new(),
                http_hooks: crate::http::HttpHooks::deny(),
                table: ResourceTable::new(),
                limits,
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.config.limits.fuel)
            .map_err(|error| Error::Configuration(error.to_string()))?;
        let invocation_started = Instant::now();
        let pause_baseline = pause.total_paused();
        let timeout = input.timeout;
        let cancellation = input.cancellation.clone();
        let callback_pause = pause.clone();
        let callback_cancellation = cancellation.clone();
        let timed_out = Arc::new(AtomicBool::new(false));
        let callback_timed_out = Arc::clone(&timed_out);
        let resident_ttl = self.config.paused_resident_ttl;
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(move |_| {
            let suspended = callback_pause.total_paused().saturating_sub(pause_baseline);
            let active = invocation_started.elapsed().saturating_sub(suspended);
            if callback_pause.is_evicted() || callback_cancellation.is_cancelled() {
                Ok(UpdateDeadline::Interrupt)
            } else if active >= timeout {
                callback_timed_out.store(true, Ordering::Release);
                Ok(UpdateDeadline::Interrupt)
            } else if callback_pause.is_paused() {
                callback_pause.mark_resident();
                let waiting_pause = callback_pause.clone();
                let waiting_cancellation = callback_cancellation.clone();
                Ok(UpdateDeadline::YieldCustom(
                    1,
                    Box::pin(async move {
                        waiting_pause
                            .wait(&waiting_cancellation, resident_ttl)
                            .await;
                    }),
                ))
            } else {
                Ok(UpdateDeadline::Yield(1))
            }
        });

        let instantiate_started = Instant::now();
        let (exit_code, instantiate, execute, suspended) = match prepared.profile {
            WasiProfile::Cli0_3 => {
                let command = wasmtime_wasi::p3::bindings::Command::instantiate_async(
                    &mut store,
                    &prepared.component,
                    &self.p3_linker,
                )
                .await
                .map_err(|error| Error::Execution(error.to_string()))?;
                let instantiate = instantiate_started.elapsed();
                let execute_started = Instant::now();
                let execute_pause_baseline = pause.total_paused();
                let result = store
                    .run_concurrent(async move |store| command.wasi_cli_run().call_run(store).await)
                    .await
                    .map_err(|error| {
                        map_execution_error(&error, &pause, &invocation_cancellation, &timed_out)
                    })?
                    .map_err(|error| {
                        map_execution_error(&error, &pause, &invocation_cancellation, &timed_out)
                    })?;
                (
                    u8::from(result.is_err()),
                    instantiate,
                    execute_started.elapsed(),
                    pause.total_paused().saturating_sub(execute_pause_baseline),
                )
            }
            WasiProfile::Cli0_2 => {
                let command = wasmtime_wasi::p2::bindings::Command::instantiate_async(
                    &mut store,
                    &prepared.component,
                    &self.p2_linker,
                )
                .await
                .map_err(|error| Error::Execution(error.to_string()))?;
                let instantiate = instantiate_started.elapsed();
                let execute_started = Instant::now();
                let execute_pause_baseline = pause.total_paused();
                let result =
                    command
                        .wasi_cli_run()
                        .call_run(&mut store)
                        .await
                        .map_err(|error| {
                            map_execution_error(
                                &error,
                                &pause,
                                &invocation_cancellation,
                                &timed_out,
                            )
                        })?;
                (
                    u8::from(result.is_err()),
                    instantiate,
                    execute_started.elapsed(),
                    pause.total_paused().saturating_sub(execute_pause_baseline),
                )
            }
            WasiProfile::Http0_3 | WasiProfile::Http0_2 => unreachable!("validated above"),
        };
        Ok(InvocationResult {
            stdout: stdout.contents().to_vec(),
            stderr: stderr.contents().to_vec(),
            exit_code,
            instantiate,
            execute,
            suspended,
        })
    }
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        self.stop_epoch.store(true, Ordering::Release);
        if let Some(thread) = self.epoch_thread.take() {
            let _ = thread.join();
        }
    }
}

pub(crate) struct HostState {
    pub(crate) wasi: WasiCtx,
    pub(crate) http: wasmtime_wasi_http::WasiHttpCtx,
    pub(crate) http_hooks: crate::http::HttpHooks,
    pub(crate) table: ResourceTable,
    pub(crate) limits: StoreLimits,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl wasmtime_wasi_http::p2::WasiHttpView for HostState {
    fn http(&mut self) -> wasmtime_wasi_http::p2::WasiHttpCtxView<'_> {
        wasmtime_wasi_http::p2::WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.http_hooks,
        }
    }
}

impl wasmtime_wasi_http::p3::WasiHttpView for HostState {
    fn http(&mut self) -> wasmtime_wasi_http::p3::WasiHttpCtxView<'_> {
        wasmtime_wasi_http::p3::WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.http_hooks,
        }
    }
}

pub(crate) struct PreparedComponent {
    pub(crate) component: Component,
    pub(crate) profile: WasiProfile,
}

struct PreparedAot {
    bytes: Vec<u8>,
    profile: WasiProfile,
}

struct InvocationResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: u8,
    instantiate: Duration,
    execute: Duration,
    suspended: Duration,
}

struct CacheEntry<T> {
    value: T,
    last_used: u64,
}

struct MemoryCache {
    warm: HashMap<String, CacheEntry<Arc<PreparedComponent>>>,
    warmish: HashMap<String, CacheEntry<Arc<PreparedAot>>>,
    warmish_bytes: usize,
    sequence: u64,
    max_warm: usize,
    max_warmish: usize,
    max_warmish_bytes: usize,
}

impl MemoryCache {
    fn new(config: &RuntimeConfig) -> Self {
        Self {
            warm: HashMap::new(),
            warmish: HashMap::new(),
            warmish_bytes: 0,
            sequence: 0,
            max_warm: config.max_warm_components,
            max_warmish: config.max_warmish_entries,
            max_warmish_bytes: config.max_warmish_bytes,
        }
    }

    fn warm(&mut self, digest: &str) -> Option<Arc<PreparedComponent>> {
        let tick = self.tick();
        let entry = self.warm.get_mut(digest)?;
        entry.last_used = tick;
        Some(Arc::clone(&entry.value))
    }

    fn warmish(&mut self, digest: &str) -> Option<Arc<PreparedAot>> {
        let tick = self.tick();
        let entry = self.warmish.get_mut(digest)?;
        entry.last_used = tick;
        Some(Arc::clone(&entry.value))
    }

    fn insert_warm(&mut self, digest: String, value: Arc<PreparedComponent>) {
        let last_used = self.tick();
        self.warm.insert(digest, CacheEntry { value, last_used });
        while self.warm.len() > self.max_warm {
            if let Some(key) = least_recent(&self.warm) {
                self.warm.remove(&key);
            }
        }
    }

    fn insert_warmish(&mut self, digest: String, value: &Arc<PreparedAot>) {
        if value.bytes.len() > self.max_warmish_bytes {
            return;
        }
        let last_used = self.tick();
        if let Some(previous) = self.warmish.insert(
            digest,
            CacheEntry {
                value: Arc::clone(value),
                last_used,
            },
        ) {
            self.warmish_bytes = self
                .warmish_bytes
                .saturating_sub(previous.value.bytes.len());
        }
        self.warmish_bytes = self.warmish_bytes.saturating_add(value.bytes.len());
        while self.warmish.len() > self.max_warmish || self.warmish_bytes > self.max_warmish_bytes {
            let Some(key) = least_recent(&self.warmish) else {
                break;
            };
            if let Some(entry) = self.warmish.remove(&key) {
                self.warmish_bytes = self.warmish_bytes.saturating_sub(entry.value.bytes.len());
            }
        }
    }

    fn demote(&mut self, digest: &str) {
        self.warm.remove(digest);
    }

    fn tick(&mut self) -> u64 {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        self.sequence
    }
}

fn least_recent<T>(entries: &HashMap<String, CacheEntry<T>>) -> Option<String> {
    entries
        .iter()
        .min_by_key(|(key, entry)| (entry.last_used, *key))
        .map(|(key, _)| key.clone())
}

#[allow(unsafe_code)]
fn deserialize_component(engine: &Engine, aot: &PreparedAot) -> Result<PreparedComponent> {
    // SAFETY: bytes reach this boundary only from Component::serialize in this
    // process or from the exact-version, exact-target, HMAC-authenticated disk
    // cache. The identity includes Wasmtime, target, compiler, and WASI profile.
    let component = unsafe { Component::deserialize(engine, &aot.bytes) }
        .map_err(|error| Error::Preparation(error.to_string()))?;
    let detected = detect_profile(engine, &component)?;
    if detected != aot.profile {
        return Err(Error::Cache(
            "deserialized component profile mismatch".to_owned(),
        ));
    }
    Ok(PreparedComponent {
        component,
        profile: detected,
    })
}

fn detect_profile(engine: &Engine, component: &Component) -> Result<WasiProfile> {
    let mut profiles = Vec::new();
    for (name, _) in component.component_type().exports(engine) {
        if name.starts_with("wasi:cli/run@0.3.") {
            profiles.push(WasiProfile::Cli0_3);
        } else if name.starts_with("wasi:cli/run@0.2.") {
            profiles.push(WasiProfile::Cli0_2);
        } else if name.starts_with("wasi:http/handler@0.3.") {
            profiles.push(WasiProfile::Http0_3);
        } else if name.starts_with("wasi:http/incoming-handler@0.2.") {
            profiles.push(WasiProfile::Http0_2);
        }
    }
    profiles.sort_by_key(|profile| profile.cache_id());
    profiles.dedup();
    match profiles.as_slice() {
        [profile] => Ok(*profile),
        [] => Err(Error::UnsupportedComponent(
            "expected a standard WASI CLI or HTTP handler export".to_owned(),
        )),
        _ => Err(Error::UnsupportedComponent(
            "component exports more than one supported WASI world".to_owned(),
        )),
    }
}

fn engine_config() -> Config {
    let mut config = Config::new();
    config
        .wasm_component_model(true)
        .wasm_component_model_async(true)
        .wasm_component_model_more_async_builtins(true)
        .wasm_component_model_async_stackful(true)
        .wasm_stack_switching(true)
        .consume_fuel(true)
        .epoch_interruption(true)
        .wasm_relaxed_simd(false)
        .wasm_simd(false)
        .memory_reservation(0)
        .memory_reservation_for_growth(0)
        .cranelift_opt_level(OptLevel::SpeedAndSize)
        .cranelift_nan_canonicalization(true);
    config
}

fn validate_config(config: &RuntimeConfig) -> Result<()> {
    if config.max_warm_components == 0
        || config.max_warmish_entries < config.max_warm_components
        || config.max_warmish_bytes == 0
        || config.background_workers == 0
        || config.paused_resident_ttl.is_zero()
        || config.epoch_interval.is_zero()
    {
        return Err(Error::Configuration(
            "cache capacities, background workers, pause TTL, and epoch interval must be positive; warmish entries must cover warm entries"
                .to_owned(),
        ));
    }
    Ok(())
}

fn spawn_epoch_ticker(
    engine: Engine,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("runtrue-wasm-epoch".to_owned())
        .spawn(move || {
            while !stop.load(Ordering::Acquire) {
                thread::sleep(interval);
                engine.increment_epoch();
            }
        })
        .map_err(|error| Error::Configuration(format!("epoch watchdog failed: {error}")))
}

fn map_execution_error(
    error: &wasmtime::Error,
    pause: &PauseToken,
    cancellation: &CancellationToken,
    timed_out: &AtomicBool,
) -> Error {
    if pause.is_evicted() {
        Error::IdleEvicted
    } else if timed_out.load(Ordering::Acquire) {
        Error::Timeout
    } else if cancellation.is_cancelled() {
        Error::Cancelled
    } else {
        Error::Execution(error.to_string())
    }
}
