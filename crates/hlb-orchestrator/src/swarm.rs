//! The Docker Swarm implementation, through `bollard`.
//!
//! All knowledge of `bollard` is confined here. The rest of the product only sees the
//! trait - which is what makes the `bollard` bet reversible.

use std::collections::HashMap;

use async_trait::async_trait;
use bollard::container::LogOutput;

use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::models::VolumeCreateOptions as CreateVolumeOptions;
use bollard::models::{
    HealthConfig, Limit, Mount, MountTypeEnum, MountVolumeOptions, MountVolumeOptionsDriverConfig,
    NetworkAttachmentConfig, NetworkCreateRequest, ResourceObject, ServiceSpecMode,
    ServiceSpecModeReplicated, ServiceSpecModeReplicatedJob, ServiceSpecRollbackConfig,
    ServiceSpecUpdateConfig, ServiceSpecUpdateConfigFailureActionEnum,
    ServiceSpecUpdateConfigOrderEnum, SwarmInitRequest, TaskSpec, TaskSpecContainerSpec,
    TaskSpecContainerSpecPrivileges, TaskSpecPlacement, TaskSpecResources, TaskSpecRestartPolicy,
    TaskSpecRestartPolicyConditionEnum,
};
use bollard::query_parameters::{
    ListNodesOptions, ListServicesOptionsBuilder, ListTasksOptionsBuilder,
    UpdateNodeOptionsBuilder, UpdateServiceOptionsBuilder,
};
use bollard::Docker;

use crate::cluster;
use crate::{
    Error, ExecOutput, JobOutcome, LogLine, Orchestrator, Result, ServiceSpec, ServiceStatus,
    TaskInfo, UpdateState, VolumeBacking, VolumeInfo, VolumeSpec,
};

const NS: i64 = 1_000_000_000;

/// What runs `docker exec` on another node: the daemon there, reached through its
/// socket. A minor pinned: the CLI negotiates the API version down to the daemon's.
pub const DOCKER_CLI_IMAGE: &str =
    "docker:28.5-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d";

/// The line a remote command's exit code is printed on, after its own output.
const EXIT_MARK: &str = "hlb-exit=";

/// The registry an image reference names, or `None` for Docker Hub: the first segment
/// is a host only when it carries a dot, a port or is `localhost`.
fn registry_host(image: &str) -> Option<&str> {
    let (first, rest) = image.split_once('/')?;
    (!rest.is_empty() && (first.contains('.') || first.contains(':') || first == "localhost"))
        .then_some(first)
}

/// The Swarm secret carrying one file of a service: named after the service, the path
/// and the content, so a new version of the file is a new secret.
fn file_secret_name(service: &str, path: &str, content: &str) -> String {
    let hex = hlb_types::token::sha256_hex(format!("{path}\n{content}").as_bytes());
    format!("{service}-file-{}", &hex[..12])
}

/// An RFC 3339 timestamp as Docker returns them, in Unix seconds.
///
/// Parsed by hand: `chrono` is present but for other reasons, and a Docker date always
/// has the same shape (`2026-08-18T10:16:04.123456789Z`). Returns `None` on anything
/// that does not fit - a half-read timestamp would put a log line in 1970, and you
/// would go looking for a clock problem.
fn unix_timestamp(s: &str) -> Option<i64> {
    let (date, remaining) = s.split_once('T')?;
    let (a, remainder_of) = date.split_once('-')?;
    let (m, j) = remainder_of.split_once('-')?;
    let time_part: String = remaining
        .chars()
        .take_while(|c| *c != '.' && *c != 'Z')
        .collect();
    let mut hms = time_part.split(':');
    let (h, mi, se) = (hms.next()?, hms.next()?, hms.next()?);

    let (a, m, j): (i64, i64, i64) = (a.parse().ok()?, m.parse().ok()?, j.parse().ok()?);
    let (h, mi, se): (i64, i64, i64) = (h.parse().ok()?, mi.parse().ok()?, se.parse().ok()?);

    // Days since the epoch, using Howard Hinnant's "civil days" algorithm. It handles
    // century leap years, which a naive division by 4 gets wrong.
    let a2 = a - i64::from(m <= 2);
    let ere = if a2 >= 0 { a2 } else { a2 - 399 } / 400;
    let year_of_era = a2 - ere * 400;
    let day_of_year = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + j - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = ere * 146_097 + day_of_era - 719_468;

    Some(days * 86_400 + h * 3_600 + mi * 60 + se)
}

/// Marks the services Homelabus manages, so the rest is never touched.
pub const MANAGED_LABEL: &str = "hlb.managed";

pub struct SwarmOrchestrator {
    docker: Docker,
    /// Credentials per registry host, sent with every service created or updated from
    /// an image of that registry.
    registries: HashMap<String, (String, String)>,
}

impl SwarmOrchestrator {
    /// `docker exec` in a container of another node, through a job placed there.
    ///
    /// A job's outcome is its log, not an exit code: the command's own code is
    /// printed last, on a line of its own, and read back from there. Public for the
    /// Swarm tests, which have one node and must still take this path.
    pub async fn exec_on_node(
        &self,
        service: &str,
        node: &str,
        container: &str,
        cmd: &[String],
    ) -> Result<ExecOutput> {
        let mut args = vec![
            "sh".to_string(),
            "-c".to_string(),
            format!("docker exec \"$0\" \"$@\" 2>&1; echo \"{EXIT_MARK}$?\""),
            container.to_string(),
        ];
        args.extend(cmd.iter().cloned());
        let mut job = ServiceSpec::new(format!("hlb-exec-{service}"), DOCKER_CLI_IMAGE)
            .job()
            .constraint(format!("node.id=={node}"))
            .bind("/var/run/docker.sock", "/var/run/docker.sock", false)
            .command(args);
        job.hardening.read_only_rootfs = false;
        let out = self.run_job(&job, 120).await?;
        let code = out
            .output
            .iter()
            .rev()
            .find_map(|l| l.trim().strip_prefix(EXIT_MARK)?.parse::<i64>().ok());
        let Some(exit_code) = code else {
            return Err(Error::Unexpected(format!(
                "the command in {service} on node {node} did not say how it ended: {}",
                out.output.join(" | ")
            )));
        };
        Ok(ExecOutput {
            exit_code,
            stdout: out
                .output
                .iter()
                .filter(|l| !l.trim().starts_with(EXIT_MARK))
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
            stderr: String::new(),
        })
    }
}

/// How many lines of a one-off job's log are read back: `logs`' own ceiling.
const JOB_LOG_ROWS: u32 = 2_000;

/// What a one-off job's run names keep of its name: the rest is [`job_name`]'s suffix,
/// within Swarm's 63 characters.
fn job_base(name: &str) -> &str {
    let mut end = name.len().min(46);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].trim_end_matches('-')
}

/// A run of the one-off job `name`: its base and a suffix no other run shares — the
/// clock, the process and a counter, as two processes may start in one clock tick.
fn job_name(name: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{}-{:08x}{:04x}{:04x}",
        job_base(name),
        t as u32,
        std::process::id() as u16,
        N.fetch_add(1, Ordering::Relaxed) as u16
    )
}

/// Is `service` a run of the job `name` — or the job itself, as runs were named before
/// they had a suffix?
fn is_run_of(service: &str, name: &str) -> bool {
    service == name
        || service
            .strip_prefix(job_base(name))
            .and_then(|r| r.strip_prefix('-'))
            .is_some_and(|r| r.len() == 16 && r.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl SwarmOrchestrator {
    /// Removes the runs of the job `name` an interrupted process left behind — those
    /// whose every task has ended. One still running is another run's, and stays.
    async fn clear_ended_runs(&self, name: &str) {
        let mut filters = HashMap::new();
        filters.insert("name".to_string(), vec![job_base(name).to_string()]);
        let opts = ListServicesOptionsBuilder::default()
            .filters(&filters)
            .build();
        let Ok(services) = self.docker.list_services(Some(opts)).await else {
            return;
        };
        for svc in services {
            let Some(service) = svc.spec.and_then(|s| s.name) else {
                continue;
            };
            if !is_run_of(&service, name) {
                continue;
            }
            let Ok(tasks) = self.read_tasks(Some(&service)).await else {
                continue;
            };
            // No task yet is a run just created, not an ended one.
            let ended = !tasks.is_empty()
                && tasks.iter().all(|t| {
                    matches!(
                        t.state.as_str(),
                        "complete" | "failed" | "rejected" | "shutdown" | "orphaned" | "remove"
                    )
                });
            if ended {
                let _ = self.docker.delete_service(&service).await;
            }
        }
    }
}

impl SwarmOrchestrator {
    /// Connects to the local daemon (Unix socket, or `DOCKER_HOST` when set).
    pub fn connect() -> Result<Self> {
        let docker = Docker::connect_with_defaults()?;
        Ok(Self {
            docker,
            registries: HashMap::new(),
        })
    }

    pub fn from_docker(docker: Docker) -> Self {
        Self {
            docker,
            registries: HashMap::new(),
        }
    }

    /// Delivers a service's files as Swarm secrets mounted at their path.
    ///
    /// Secrets rather than configs: `bollard` 0.19 has no configs API, and a secret is
    /// encrypted at rest in the Raft log besides — a configuration file that some day
    /// carries a token stays protected.
    ///
    /// ⚠️ A Swarm secret is IMMUTABLE. The name carries a hash of the content, so a
    /// changed file is a new secret rather than an update Swarm would refuse.
    async fn file_secrets(
        &self,
        service: &str,
        files: &[(String, String)],
    ) -> Result<Vec<bollard::models::TaskSpecContainerSpecSecrets>> {
        let mut out = Vec::new();
        for (path, content) in files {
            let name = file_secret_name(service, path, content);
            let id = match self.docker.inspect_secret(&name).await {
                Ok(s) => s.id,
                Err(_) => {
                    let mut labels = HashMap::new();
                    labels.insert(MANAGED_LABEL.to_string(), "true".to_string());
                    self.docker
                        .create_secret(bollard::models::SecretSpec {
                            name: Some(name.clone()),
                            labels: Some(labels),
                            data: Some(hlb_types::token::base64_standard(content.as_bytes())),
                            ..Default::default()
                        })
                        .await?
                        .id
                        .into()
                }
            };
            out.push(bollard::models::TaskSpecContainerSpecSecrets {
                file: Some(bollard::models::TaskSpecContainerSpecFile {
                    name: Some(path.clone()),
                    uid: Some("0".into()),
                    gid: Some("0".into()),
                    // Readable by the service's own user, whatever it is.
                    mode: Some(0o444),
                }),
                secret_id: id,
                secret_name: Some(name),
            });
        }
        Ok(out)
    }

    /// Puts the ingress network at [`crate::OVERLAY_MTU`].
    ///
    /// `swarm init` creates it at 1500, and it can only be replaced while no service
    /// publishes a port through it — so a published port leaves it as it is, said in the
    /// log rather than broken.
    ///
    /// ⚠️ Both edges are asynchronous: `remove` returns before the network is gone, and
    /// even once `inspect` stops finding it, `create` can still answer "already exists"
    /// for a moment (seen on a fresh Debian 12 node, never on Docker-in-Docker). The
    /// creation is retried rather than trusted to the first answer.
    async fn ensure_ingress(&self) -> Result<()> {
        let mtu = crate::OVERLAY_MTU.to_string();
        if let Ok(n) = self
            .docker
            .inspect_network(
                "ingress",
                None::<bollard::query_parameters::InspectNetworkOptions>,
            )
            .await
        {
            let current = n
                .options
                .as_ref()
                .and_then(|o| o.get("com.docker.network.driver.mtu").cloned());
            if current.as_deref() == Some(mtu.as_str()) {
                return Ok(());
            }
            let publishing = self
                .docker
                .list_services(None::<bollard::query_parameters::ListServicesOptions>)
                .await?
                .iter()
                .any(|s| {
                    s.endpoint
                        .as_ref()
                        .and_then(|e| e.ports.as_ref())
                        .is_some_and(|p| !p.is_empty())
                });
            if publishing {
                tracing::warn!(
                    "ingress network at the default MTU, and a service publishes through \
                     it: left as it is — large responses through published ports may stall"
                );
                return Ok(());
            }
            self.docker.remove_network("ingress").await?;
            self.wait_for_network("ingress", false).await?;
        }

        let mut options = HashMap::new();
        options.insert("com.docker.network.driver.mtu".to_string(), mtu);
        let mut last = None;
        for _ in 0..20 {
            match self
                .docker
                .create_network(NetworkCreateRequest {
                    name: "ingress".to_string(),
                    driver: Some("overlay".to_string()),
                    ingress: Some(true),
                    options: Some(options.clone()),
                    ..Default::default()
                })
                .await
            {
                Ok(_) => {
                    tracing::info!(mtu = crate::OVERLAY_MTU, "ingress network recreated");
                    return Ok(());
                }
                Err(e) => {
                    last = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        Err(last
            .map(Error::from)
            .unwrap_or_else(|| Error::Unexpected("ingress network not recreated".into())))
    }

    async fn network_exists(&self, name: &str) -> bool {
        self.docker
            .inspect_network(
                name,
                None::<bollard::query_parameters::InspectNetworkOptions>,
            )
            .await
            .is_ok()
    }

    /// Waits up to 20 s for a network to appear (`present`) or to be gone.
    async fn wait_for_network(&self, name: &str, present: bool) -> Result<()> {
        for _ in 0..40 {
            if self.network_exists(name).await == present {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        Err(Error::Unexpected(format!(
            "network \"{name}\" still {} after 20 s",
            if present { "absent" } else { "present" }
        )))
    }

    /// Credentials for a private registry.
    ///
    /// 🔴 A node does not pull a service's image with the `docker login` done on it: the
    /// Swarm daemon never reads `~/.docker/config.json`. The credentials travel with the
    /// service — what `docker service create --with-registry-auth` does — or every node
    /// fails on "pull access denied" with a perfectly good login in place.
    pub fn with_registry_auth(
        mut self,
        host: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        self.registries
            .insert(host.into(), (user.into(), password.into()));
        self
    }

    /// The credentials for an image's registry, when some were given for it.
    fn credentials_for(&self, image: &str) -> Option<bollard::auth::DockerCredentials> {
        let host = registry_host(image)?;
        let (user, password) = self.registries.get(host)?;
        Some(bollard::auth::DockerCredentials {
            username: Some(user.clone()),
            password: Some(password.clone()),
            serveraddress: Some(host.to_string()),
            ..Default::default()
        })
    }

    /// The update policy, applied to **every** deployed service.
    ///
    /// This is not configurable per app: it is the foundation that makes automatic
    /// rollback possible. An app that cannot cope belongs on `pin`. The order alone
    /// follows from where the data is, never from a manifest.
    fn update_config(stops_first: bool) -> ServiceSpecUpdateConfig {
        ServiceSpecUpdateConfig {
            // One task at a time: the whole service is never replaced at once.
            parallelism: Some(1),
            // The new task starts before the old one stops → no downtime. 🔴 Except
            // where both would open the same data: restarting PostgreSQL ran two
            // postmasters on one directory, the new one lost its lock file and shut
            // down hard, and the next one replayed its WAL (found on a real cluster).
            // And where both would need the same port of the same node (host mode):
            // the new task waits for a port the old one holds, for ever.
            order: Some(if stops_first {
                ServiceSpecUpdateConfigOrderEnum::STOP_FIRST
            } else {
                ServiceSpecUpdateConfigOrderEnum::START_FIRST
            }),
            // The heart of it: Swarm rolls back a failing update itself.
            failure_action: Some(ServiceSpecUpdateConfigFailureActionEnum::ROLLBACK),
            // Watches for 30 s after startup: a container that dies at the fifth
            // second must count as a failure, not a success.
            monitor: Some(30 * NS),
            max_failure_ratio: Some(0.0),
            delay: Some(5 * NS),
        }
    }

    /// Rolling back must be more careful than rolling forward: stop first, to avoid
    /// two versions coexisting over an already-migrated schema.
    fn rollback_config() -> ServiceSpecRollbackConfig {
        ServiceSpecRollbackConfig {
            parallelism: Some(1),
            order: Some(bollard::models::ServiceSpecRollbackConfigOrderEnum::STOP_FIRST),
            failure_action: Some(
                bollard::models::ServiceSpecRollbackConfigFailureActionEnum::PAUSE,
            ),
            monitor: Some(30 * NS),
            max_failure_ratio: Some(0.0),
            delay: Some(5 * NS),
        }
    }

    fn to_bollard(spec: &ServiceSpec) -> bollard::models::ServiceSpec {
        let mut labels: HashMap<String, String> = spec.labels.iter().cloned().collect();
        labels.insert(MANAGED_LABEL.to_string(), "true".to_string());

        bollard::models::ServiceSpec {
            name: Some(spec.name.clone()),
            labels: Some(labels),
            task_template: Some(TaskSpec {
                container_spec: Some(TaskSpecContainerSpec {
                    image: Some(spec.image.clone()),
                    command: if spec.command.is_empty() {
                        None
                    } else {
                        Some(spec.command.clone())
                    },
                    env: Some(spec.env.iter().map(|(k, v)| format!("{k}={v}")).collect()),

                    // Hardening actually passed to Swarm, not merely declared in the
                    // manifest.
                    read_only: Some(spec.hardening.read_only_rootfs),
                    user: spec.hardening.user.clone(),
                    capability_drop: if spec.hardening.cap_drop.is_empty() {
                        None
                    } else {
                        Some(spec.hardening.cap_drop.clone())
                    },
                    capability_add: if spec.hardening.cap_add.is_empty() {
                        None
                    } else {
                        Some(spec.hardening.cap_add.clone())
                    },
                    // `no-new-privileges` has no dedicated field: it goes through the
                    // security options, as on the Docker command line.
                    privileges: Some(TaskSpecContainerSpecPrivileges {
                        no_new_privileges: Some(spec.hardening.no_new_privileges),
                        ..Default::default()
                    }),

                    // Declared volumes are actually attached: without this, data would
                    // live in the container's ephemeral layer.
                    mounts: if spec.mounts.is_empty()
                        && spec.binds.is_empty()
                        && spec.hardening.tmpfs.is_empty()
                    {
                        None
                    } else {
                        Some(
                            spec.mounts
                                .iter()
                                .map(|(vol, path)| Mount {
                                    target: Some(path.clone()),
                                    source: Some(vol.clone()),
                                    typ: Some(MountTypeEnum::VOLUME),
                                    // What makes a node other than this one create
                                    // the volume as NFS, or as the bind, it is.
                                    volume_options: spec.backing_of(vol).driver_options().map(
                                        |options| MountVolumeOptions {
                                            driver_config: Some(MountVolumeOptionsDriverConfig {
                                                name: Some("local".into()),
                                                options: Some(options),
                                            }),
                                            // Docker's first-mount copy of the image's
                                            // directory chowns the export, which
                                            // `all_squash` refuses: the task was
                                            // rejected on "lchown: operation not
                                            // permitted". A share is not seeded from
                                            // an image anyway.
                                            no_copy: matches!(
                                                spec.backing_of(vol),
                                                VolumeBacking::Nfs { .. }
                                            )
                                            .then_some(true),
                                            ..Default::default()
                                        },
                                    ),
                                    ..Default::default()
                                })
                                .chain(spec.binds.iter().map(|b| Mount {
                                    target: Some(b.target.clone()),
                                    source: Some(b.source.clone()),
                                    typ: Some(MountTypeEnum::BIND),
                                    read_only: Some(b.read_only),
                                    ..Default::default()
                                }))
                                .chain(spec.hardening.tmpfs.iter().map(|path| Mount {
                                    target: Some(path.clone()),
                                    typ: Some(MountTypeEnum::TMPFS),
                                    // 🔴 Root's 0755 otherwise: Fluxer's api, run as
                                    // 65532, could not open its socket there (EACCES).
                                    // Sticky and open to all, as `/tmp` is.
                                    tmpfs_options: Some(bollard::models::MountTmpfsOptions {
                                        mode: Some(0o1777),
                                        ..Default::default()
                                    }),
                                    ..Default::default()
                                }))
                                .collect(),
                        )
                    },

                    health_check: spec.healthcheck.as_ref().map(|h| HealthConfig {
                        test: Some(h.test.clone()),
                        // Swarm expects nanoseconds.
                        interval: Some((h.interval_secs * 1_000_000_000) as i64),
                        timeout: Some((h.timeout_secs * 1_000_000_000) as i64),
                        retries: Some(h.retries as i64),
                        start_period: Some((h.start_period_secs * 1_000_000_000) as i64),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                placement: Some(TaskSpecPlacement {
                    constraints: Some(spec.constraints.clone()),
                    ..Default::default()
                }),
                // The reservation is what Swarm places by — a node without that much
                // unreserved says "insufficient resources" instead of an OOM later.
                resources: spec.memory.map(|m| TaskSpecResources {
                    limits: Some(Limit {
                        memory_bytes: i64::try_from(m.limit.0).ok(),
                        ..Default::default()
                    }),
                    reservations: Some(ResourceObject {
                        memory_bytes: i64::try_from(m.reserve.0).ok(),
                        ..Default::default()
                    }),
                }),
                // 🔴 A job that failed is not run again: a refused Caddyfile retried in
                // a loop would only repeat its refusal, and never say it was final.
                restart_policy: (spec.mode == crate::ServiceMode::Job).then(|| {
                    TaskSpecRestartPolicy {
                        condition: Some(TaskSpecRestartPolicyConditionEnum::NONE),
                        ..Default::default()
                    }
                }),
                // 🔴 Without it a service is on no overlay at all: it starts, looks
                // healthy, and cannot resolve `postgres` — the app then reports a
                // database error that names a host, never a network.
                networks: if spec.networks.is_empty() {
                    None
                } else {
                    Some(
                        spec.networks
                            .iter()
                            .map(|n| NetworkAttachmentConfig {
                                target: Some(n.clone()),
                                aliases: (!spec.aliases.is_empty()).then(|| {
                                    let mut a = spec.aliases.clone();
                                    a.sort();
                                    a.dedup();
                                    a
                                }),
                                ..Default::default()
                            })
                            .collect(),
                    )
                },
                ..Default::default()
            }),
            mode: Some(match spec.mode {
                crate::ServiceMode::Global => ServiceSpecMode {
                    // `replicas` is meaningless here: Swarm places exactly one per
                    // node, and adds one automatically for each new node. Global mode
                    // is signalled by an empty object in the Docker API.
                    global: Some(HashMap::new()),
                    ..Default::default()
                },
                crate::ServiceMode::Replicated => ServiceSpecMode {
                    replicated: Some(ServiceSpecModeReplicated {
                        replicas: Some(spec.replicas as i64),
                    }),
                    ..Default::default()
                },
                crate::ServiceMode::Job => ServiceSpecMode {
                    replicated_job: Some(ServiceSpecModeReplicatedJob {
                        max_concurrent: Some(1),
                        total_completions: Some(1),
                    }),
                    ..Default::default()
                },
            }),
            // A job is never updated nor rolled back: it runs once.
            update_config: (spec.mode != crate::ServiceMode::Job)
                .then(|| Self::update_config(spec.stops_first())),
            rollback_config: (spec.mode != crate::ServiceMode::Job).then(Self::rollback_config),
            // In HOST mode: bound on the node running the task, the client's address
            // intact. Through the ingress mesh every connection would come from an
            // overlay address — an SMTP server would see one sender for the whole
            // internet, and every check keyed on it would be meaningless.
            endpoint_spec: if spec.hardening.published_ports.is_empty() {
                None
            } else {
                Some(bollard::models::EndpointSpec {
                    ports: Some(
                        spec.hardening
                            .published_ports
                            .iter()
                            .map(|p| bollard::models::EndpointPortConfig {
                                protocol: Some(match p.protocol {
                                    hlb_types::manifest::Protocol::Tcp => {
                                        bollard::models::EndpointPortConfigProtocolEnum::TCP
                                    }
                                    hlb_types::manifest::Protocol::Udp => {
                                        bollard::models::EndpointPortConfigProtocolEnum::UDP
                                    }
                                }),
                                target_port: Some(i64::from(p.port)),
                                published_port: Some(i64::from(p.port)),
                                publish_mode: Some(
                                    bollard::models::EndpointPortConfigPublishModeEnum::HOST,
                                ),
                                ..Default::default()
                            })
                            .collect(),
                    ),
                    ..Default::default()
                })
            },
            ..Default::default()
        }
    }

    /// Counts the tasks actually running.
    ///
    /// ⚠️ Swarm keeps the history of dead tasks: `TaskInfo::is_alive` requires
    /// `desired_state` **and** `state`, or corpses get counted. The rule lives there and
    /// not here - two implementations would eventually diverge, and the divergence would
    /// give a service you believe is up.
    async fn running_tasks(&self, service: &str) -> Result<usize> {
        Ok(self
            .read_tasks(Some(service))
            .await?
            .iter()
            .filter(|t| t.is_alive())
            .count())
    }

    /// The tasks, as Swarm returns them.
    ///
    /// With no state filter: dead tasks are what explains an outage.
    async fn read_tasks(&self, service: Option<&str>) -> Result<Vec<TaskInfo>> {
        let mut filters = HashMap::new();
        match service {
            Some(s) => {
                filters.insert("service".to_string(), vec![s.to_string()]);
            }
            None => {
                // With no service filter we restrict to what Homelabus manages: the
                // Swarm's other services are none of our business, and showing them
                // would suggest we drive them.
                filters.insert("label".to_string(), vec![MANAGED_LABEL.to_string()]);
            }
        }

        let opts = ListTasksOptionsBuilder::default().filters(&filters).build();
        let tasks = self.docker.list_tasks(Some(opts)).await?;

        // 🔴 A task names its service by Swarm id only, and the label that was read
        // for the name is on the container, never on the task: every screen showing a
        // task's service showed `mky0…`, and every comparison with a name failed. The
        // services are listed once to translate.
        let names: HashMap<String, String> = self
            .docker
            .list_services(None::<bollard::query_parameters::ListServicesOptions>)
            .await?
            .into_iter()
            .filter_map(|s| Some((s.id?, s.spec?.name?)))
            .collect();

        Ok(tasks
            .iter()
            .map(|t| Self::to_task_info(t, &names))
            .collect())
    }

    fn to_task_info(t: &bollard::models::Task, names: &HashMap<String, String>) -> TaskInfo {
        let status = t.status.as_ref();
        TaskInfo {
            id: t.id.clone().unwrap_or_default(),
            // A service removed since its task was listed keeps its id: there is no
            // name left to give.
            service: t
                .service_id
                .as_ref()
                .map(|id| names.get(id).unwrap_or(id).clone())
                .unwrap_or_default(),
            slot: t.slot.map(|s| s as u64),
            node_id: t.node_id.clone().filter(|n| !n.is_empty()),
            desired_state: t
                .desired_state
                .map(|d| format!("{d:?}").to_lowercase())
                .unwrap_or_default(),
            state: status
                .and_then(|s| s.state)
                .map(|s| format!("{s:?}").to_lowercase())
                .unwrap_or_default(),
            image: t
                .spec
                .as_ref()
                .and_then(|sp| sp.container_spec.as_ref())
                .and_then(|c| c.image.clone())
                .unwrap_or_default(),
            message: status
                .and_then(|s| s.message.clone())
                .filter(|m| !m.is_empty()),
            err: status.and_then(|s| s.err.clone()).filter(|e| !e.is_empty()),
            updated_at: status
                .and_then(|s| s.timestamp.as_deref())
                .and_then(unix_timestamp),
        }
    }

    fn parse_update_state(s: Option<&str>) -> Option<UpdateState> {
        s.map(|s| match s {
            "updating" => UpdateState::Updating,
            "paused" => UpdateState::Paused,
            "completed" => UpdateState::Completed,
            "rollback_started" => UpdateState::RollbackStarted,
            "rollback_paused" => UpdateState::RollbackPaused,
            "rollback_completed" => UpdateState::RollbackCompleted,
            _ => UpdateState::Unknown,
        })
    }

    /// The service as Swarm holds it, to be written back — its probe included, which
    /// bollard reads as none.
    ///
    /// 🔴 bollard's `ContainerSpec` names the probe `HealthCheck`; Docker writes it
    /// `Healthcheck`. Go reads JSON keys without case, so a service CREATED with it has
    /// it; serde does not, so every spec READ came back without it — and every
    /// read-modify-write (an image moved, a scale, a restart) wrote the service back
    /// with no probe. The image's own then ran: the catalog's PostgreSQL, its
    /// `healthcheck.sh` signing in as `root`, stayed "starting" and down (the lab,
    /// 2026-10-19). Read again here through the CLI, which names it as Docker does.
    async fn inspect_whole(&self, name: &str) -> Result<bollard::models::Service> {
        let mut svc = self.inspect(name).await?;
        let cs = svc
            .spec
            .as_mut()
            .and_then(|s| s.task_template.as_mut())
            .and_then(|t| t.container_spec.as_mut());
        if let Some(cs) = cs.filter(|c| c.health_check.is_none()) {
            cs.health_check = Self::probe_of(name).await?;
        }
        Ok(svc)
    }

    async fn inspect(&self, name: &str) -> Result<bollard::models::Service> {
        self.docker
            .inspect_service(
                name,
                None::<bollard::query_parameters::InspectServiceOptions>,
            )
            .await
            .map_err(|e| match e {
                bollard::errors::Error::DockerResponseServerError {
                    status_code: 404, ..
                } => Error::NotFound(name.to_string()),
                other => Error::Docker(other),
            })
    }

    /// A service's probe, as `docker service inspect` prints it.
    async fn probe_of(name: &str) -> Result<Option<bollard::models::HealthConfig>> {
        let out = tokio::process::Command::new("docker")
            .args([
                "service",
                "inspect",
                "--format",
                "{{json .Spec.TaskTemplate.ContainerSpec.Healthcheck}}",
                name,
            ])
            .output()
            .await
            .map_err(|e| {
                Error::Unexpected(format!(
                    "docker not found, which reads {name}'s probe: written back without \
                     it, the service would lose it ({e})"
                ))
            })?;
        if !out.status.success() {
            return Err(Error::Unexpected(format!(
                "{name}'s probe could not be read: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let text = text.trim();
        if text.is_empty() || text == "null" {
            return Ok(None);
        }
        serde_json::from_str(text)
            .map(Some)
            .map_err(|e| Error::Unexpected(format!("{name}'s probe is unreadable: {e}")))
    }

    fn to_status(svc: &bollard::models::Service, running: usize) -> ServiceStatus {
        let spec = svc.spec.as_ref();
        ServiceStatus {
            name: spec.and_then(|s| s.name.clone()).unwrap_or_default(),
            id: svc.id.clone().unwrap_or_default(),
            desired_replicas: spec
                .and_then(|s| s.mode.as_ref())
                .and_then(|m| m.replicated.as_ref())
                .and_then(|r| r.replicas)
                .unwrap_or(0) as u64,
            running_replicas: running,
            image: spec
                .and_then(|s| s.task_template.as_ref())
                .and_then(|t| t.container_spec.as_ref())
                .and_then(|c| c.image.clone())
                .unwrap_or_default(),
            update_state: Self::parse_update_state(
                svc.update_status
                    .as_ref()
                    .and_then(|u| u.state.as_ref())
                    .map(|s| s.to_string())
                    .as_deref(),
            ),
        }
    }
}

impl SwarmOrchestrator {
    /// Labels the node that holds the service's data, and constrains it there.
    async fn pin_to_its_data(&self, spec: &ServiceSpec) -> Result<ServiceSpec> {
        let nodes = self.docker.list_nodes(None::<ListNodesOptions>).await?;
        let candidates: Vec<cluster::Candidate> = nodes
            .iter()
            .map(|n| {
                let s = n.spec.clone().unwrap_or_default();
                let ready = n
                    .status
                    .as_ref()
                    .and_then(|st| st.state)
                    .is_some_and(|st| format!("{st:?}").eq_ignore_ascii_case("ready"));
                let active = s
                    .availability
                    .is_some_and(|a| format!("{a:?}").eq_ignore_ascii_case("active"));
                cluster::Candidate {
                    id: n.id.clone().unwrap_or_default(),
                    hostname: n
                        .description
                        .as_ref()
                        .and_then(|d| d.hostname.clone())
                        .unwrap_or_default(),
                    available: ready && active,
                    labels: s.labels.unwrap_or_default().into_iter().collect(),
                }
            })
            .collect();
        // A volume bound on the pool exists on the storage node only: anywhere else the
        // bind finds no directory and the task never starts.
        let mut constraints = spec.constraints.clone();
        if spec
            .mounts
            .iter()
            .any(|(v, _)| matches!(spec.backing_of(v), VolumeBacking::Bind { .. }))
        {
            constraints.push(format!("node.labels.{}==true", cluster::LABEL_STORAGE));
        }
        let node =
            cluster::data_node(&spec.name, &candidates, &constraints).map_err(Error::Unexpected)?;
        let label = cluster::data_label(&spec.name);
        if !candidates
            .iter()
            .any(|c| c.id == node && c.labels.get(&label).is_some_and(|v| v == "true"))
        {
            self.label_node(&node, &label, "true").await?;
            tracing::info!(service = %spec.name, node, "data pinned to its node");
        }
        let mut pinned = spec.clone();
        pinned
            .constraints
            .push(cluster::data_constraint(&spec.name));
        Ok(pinned)
    }
}

/// Whether a service read back from Swarm must stop before its next task starts: it
/// keeps data on its node (its data constraint says so), or holds a port of its node.
fn stops_first(spec: &bollard::models::ServiceSpec) -> bool {
    let pinned = spec
        .task_template
        .as_ref()
        .and_then(|t| t.placement.as_ref())
        .and_then(|p| p.constraints.as_ref())
        .is_some_and(|c| {
            let prefix = format!("node.labels.{}", cluster::data_label(""));
            c.iter().any(|c| c.starts_with(&prefix))
        });
    let holds_a_port = spec
        .endpoint_spec
        .as_ref()
        .and_then(|e| e.ports.as_ref())
        .is_some_and(|ports| {
            ports.iter().any(|p| {
                p.publish_mode == Some(bollard::models::EndpointPortConfigPublishModeEnum::HOST)
            })
        });
    pinned || holds_a_port
}

#[async_trait]
impl Orchestrator for SwarmOrchestrator {
    async fn ping(&self) -> Result<String> {
        let v = self.docker.version().await?;
        Ok(v.version.unwrap_or_else(|| "unknown".into()))
    }

    async fn deploy(&self, spec: &ServiceSpec) -> Result<String> {
        let pinned;
        let spec = if spec.keeps_data_on_its_node() {
            pinned = self.pin_to_its_data(spec).await?;
            &pinned
        } else {
            spec
        };
        let mut service = Self::to_bollard(spec);
        let files = self.file_secrets(&spec.name, &spec.files).await?;
        if !files.is_empty() {
            if let Some(c) = service
                .task_template
                .as_mut()
                .and_then(|t| t.container_spec.as_mut())
            {
                c.secrets = Some(files);
            }
        }
        // An existing service is updated in place, under its update policy: rerunning
        // an install, or applying a catalog change, must change the running service —
        // creating it again was refused by Swarm, and skipping it left it as it was.
        match self.inspect(&spec.name).await {
            Ok(current) => {
                let id = current.id.clone().unwrap_or_default();
                let version = current
                    .version
                    .and_then(|v| v.index)
                    .ok_or_else(|| Error::Unexpected("service with no version".into()))?;
                let opts = UpdateServiceOptionsBuilder::default()
                    .version(version as i32)
                    .build();
                self.docker
                    .update_service(&spec.name, service, opts, self.credentials_for(&spec.image))
                    .await?;
                Ok(id)
            }
            Err(Error::NotFound(_)) => {
                let resp = self
                    .docker
                    .create_service(service, self.credentials_for(&spec.image))
                    .await?;
                resp.id
                    .ok_or_else(|| Error::Unexpected("creation returned no id".into()))
            }
            Err(e) => Err(e),
        }
    }

    async fn update_image(&self, name: &str, image: &str) -> Result<()> {
        let current = self.inspect_whole(name).await?;

        // Swarm requires the current version: this is optimistic concurrency control.
        // Without it, two simultaneous updates overwrite each other.
        let version = current
            .version
            .and_then(|v| v.index)
            .ok_or_else(|| Error::Unexpected("service with no version".into()))?;

        let mut spec = current
            .spec
            .ok_or_else(|| Error::Unexpected("service with no spec".into()))?;

        // Only the image is replaced: the rest of the spec is kept as-is.
        if let Some(tt) = spec.task_template.as_mut() {
            if let Some(cs) = tt.container_spec.as_mut() {
                cs.image = Some(image.to_string());
            }
        }
        // And the policy is reasserted, in case the service was created elsewhere.
        spec.update_config = Some(Self::update_config(stops_first(&spec)));
        spec.rollback_config = Some(Self::rollback_config());

        let opts = UpdateServiceOptionsBuilder::default()
            .version(version as i32)
            .build();

        self.docker
            .update_service(name, spec, opts, self.credentials_for(image))
            .await?;
        Ok(())
    }

    async fn run_job(&self, spec: &ServiceSpec, timeout_secs: u64) -> Result<JobOutcome> {
        // 🔴 A run of its own name. Every run deleted any service of the job's name
        // first, "left by an interrupted run": a second backup or restore of one app,
        // a second exec in one service, killed the first midway — and the killed run
        // then read the other's tasks and log as its own, a success with the other's
        // snapshot id. Only runs that have ENDED are cleared now.
        self.clear_ended_runs(&spec.name).await;
        let mut spec = spec.clone();
        spec.name = job_name(&spec.name);
        let spec = &spec;
        let mut service = Self::to_bollard(spec);
        let files = self.file_secrets(&spec.name, &spec.files).await?;
        let secrets: Vec<String> = files.iter().filter_map(|f| f.secret_name.clone()).collect();
        if let Some(c) = service
            .task_template
            .as_mut()
            .and_then(|t| t.container_spec.as_mut())
        {
            c.secrets = Some(files);
        }
        self.docker
            .create_service(service, self.credentials_for(&spec.image))
            .await?;

        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);
        let outcome = loop {
            let tasks = self.read_tasks(Some(&spec.name)).await?;
            if tasks.iter().any(|t| t.state == "complete") {
                break Some(true);
            }
            if tasks
                .iter()
                .any(|t| matches!(t.state.as_str(), "failed" | "rejected" | "orphaned"))
            {
                break Some(false);
            }
            if tokio::time::Instant::now() >= deadline {
                break None;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        };
        // An unreadable log is said, never read as an empty one: without the `docker`
        // binary, a job on another node that ran fine "did not say how it ended", and
        // nothing named the missing binary.
        // The whole log, up to the ceiling: an exec's caller judges its output, and the
        // last twenty lines missed what a probe looks for.
        let mut output: Vec<String> = match self.logs(&spec.name, JOB_LOG_ROWS).await {
            Ok(lines) => lines.into_iter().map(|l| l.line).collect(),
            Err(e) => vec![format!("its log could not be read: {e}")],
        };
        let swarm_says = || async {
            self.read_tasks(Some(&spec.name))
                .await
                .ok()
                .and_then(|t| crate::why_not_running(&t))
        };
        match outcome {
            None => output.push(format!(
                "did not end within {timeout_secs} s{}",
                swarm_says()
                    .await
                    .map(|w| format!(" — Swarm says: {w}"))
                    .unwrap_or_default()
            )),
            // A task that never ran wrote no log: the refusal read "refused: " and
            // nothing — Swarm's own reason is all there is.
            Some(false) if output.is_empty() => output.push(
                swarm_says()
                    .await
                    .unwrap_or_else(|| "the job failed and wrote nothing".into()),
            ),
            Some(_) => {}
        }
        let _ = self.docker.delete_service(&spec.name).await;
        // The file may carry a credential: it does not outlive the one task that read it.
        for name in secrets {
            for _ in 0..10 {
                if self.docker.delete_secret(&name).await.is_ok() {
                    break;
                }
                // Refused while the task's container still holds it.
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            }
        }
        Ok(JobOutcome {
            succeeded: outcome == Some(true),
            output,
        })
    }

    async fn reconfigure(
        &self,
        name: &str,
        files: &[(String, String)],
        aliases: &[String],
    ) -> Result<bool> {
        let current = self.inspect_whole(name).await?;
        let version = current
            .version
            .and_then(|v| v.index)
            .ok_or_else(|| Error::Unexpected("service with no version".into()))?;
        let mut spec = current
            .spec
            .ok_or_else(|| Error::Unexpected("service with no spec".into()))?;

        let fresh = self.file_secrets(name, files).await?;
        let tt = spec
            .task_template
            .as_mut()
            .ok_or_else(|| Error::Unexpected("service with no task template".into()))?;
        let mut changed = false;

        if let Some(cs) = tt.container_spec.as_mut() {
            let target = |s: &bollard::models::TaskSpecContainerSpecSecrets| {
                s.file.as_ref().and_then(|f| f.name.clone())
            };
            let mut secrets = cs.secrets.take().unwrap_or_default();
            for new in fresh {
                match secrets.iter_mut().find(|s| target(s) == target(&new)) {
                    Some(old) if old.secret_name == new.secret_name => {}
                    Some(old) => {
                        *old = new;
                        changed = true;
                    }
                    None => {
                        secrets.push(new);
                        changed = true;
                    }
                }
            }
            cs.secrets = Some(secrets);
        }

        let mut wanted = aliases.to_vec();
        wanted.sort();
        wanted.dedup();
        for n in tt.networks.iter_mut().flatten() {
            let mut have = n.aliases.clone().unwrap_or_default();
            have.sort();
            if have != wanted {
                n.aliases = (!wanted.is_empty()).then(|| wanted.clone());
                changed = true;
            }
        }
        if !changed {
            return Ok(false);
        }

        let image = tt
            .container_spec
            .as_ref()
            .and_then(|c| c.image.clone())
            .unwrap_or_default();
        // The policy is reasserted, as for an image.
        spec.update_config = Some(Self::update_config(stops_first(&spec)));
        spec.rollback_config = Some(Self::rollback_config());

        let opts = UpdateServiceOptionsBuilder::default()
            .version(version as i32)
            .build();
        self.docker
            .update_service(name, spec, opts, self.credentials_for(&image))
            .await?;
        Ok(true)
    }

    async fn scale(&self, name: &str, replicas: u64) -> Result<()> {
        let current = self.inspect_whole(name).await?;
        let version = current
            .version
            .and_then(|v| v.index)
            .ok_or_else(|| Error::Unexpected("service with no version".into()))?;

        let mut spec = current
            .spec
            .ok_or_else(|| Error::Unexpected("service with no spec".into()))?;

        // Only the mode is touched: the rest of the spec is kept intact.
        spec.mode = Some(ServiceSpecMode {
            replicated: Some(ServiceSpecModeReplicated {
                replicas: Some(replicas as i64),
            }),
            ..Default::default()
        });

        let opts = UpdateServiceOptionsBuilder::default()
            .version(version as i32)
            .build();

        self.docker.update_service(name, spec, opts, None).await?;
        Ok(())
    }

    async fn cluster_init(&self, advertise_addr: &str) -> Result<String> {
        // Idempotent: reinitialising an active Swarm would destroy the existing cluster.
        // A rerun still finishes what a first run left half done: the ingress.
        if let Ok(s) = self.docker.inspect_swarm().await {
            if let Some(id) = s.id {
                tracing::debug!("Swarm already active, kept");
                self.ensure_ingress().await?;
                return Ok(id);
            }
        }

        let opts = SwarmInitRequest {
            // Listening on the advertised address alone: with `0.0.0.0` the cluster
            // API answers on every interface, the public one included, whatever the
            // nodes are told to use.
            listen_addr: Some(format!("{advertise_addr}:2377")),
            advertise_addr: Some(advertise_addr.to_string()),
            ..Default::default()
        };

        let id = self.docker.init_swarm(opts).await?;
        tracing::info!(%id, "Swarm initialised");
        self.wait_for_network("ingress", true).await?;
        self.ensure_ingress().await?;
        Ok(id)
    }

    async fn ensure_network(&self, name: &str) -> Result<bool> {
        if self.network_exists(name).await {
            return Ok(false);
        }
        let mut options = HashMap::new();
        options.insert(
            "com.docker.network.driver.mtu".to_string(),
            crate::OVERLAY_MTU.to_string(),
        );
        let mut labels = HashMap::new();
        labels.insert(MANAGED_LABEL.to_string(), "true".to_string());
        self.docker
            .create_network(NetworkCreateRequest {
                name: name.to_string(),
                driver: Some("overlay".to_string()),
                // Attachable: the dump and restore containers `hlb backup` starts are
                // plain containers, and must reach `postgres` by name too.
                attachable: Some(true),
                options: Some(options),
                labels: Some(labels),
                ..Default::default()
            })
            .await?;
        tracing::info!(network = name, "overlay network created");
        Ok(true)
    }

    async fn network_subnets(&self, name: &str) -> Result<Vec<String>> {
        let n = self
            .docker
            .inspect_network(
                name,
                None::<bollard::query_parameters::InspectNetworkOptions>,
            )
            .await?;
        Ok(n.ipam
            .and_then(|i| i.config)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|c| c.subnet)
            .collect())
    }

    async fn service_address(&self, service: &str, network: &str) -> Result<Option<String>> {
        let svc = match self.inspect(service).await {
            Ok(s) => s,
            Err(Error::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let net = self
            .docker
            .inspect_network(
                network,
                None::<bollard::query_parameters::InspectNetworkOptions>,
            )
            .await?;
        Ok(svc
            .endpoint
            .and_then(|e| e.virtual_ips)
            .unwrap_or_default()
            .into_iter()
            .find(|v| v.network_id.is_some() && v.network_id == net.id)
            // `10.0.1.5/24`: the address alone.
            .and_then(|v| v.addr)
            .map(|a| a.split('/').next().unwrap_or_default().to_string()))
    }

    async fn enable_autolock(&self) -> Result<String> {
        // ⚠️ `bollard` 0.19 exposes neither `update_swarm` nor `get_swarm_unlock_key`,
        // so this goes through the Docker CLI — as do a service's logs, and it is said
        // rather than hidden.
        let out = tokio::process::Command::new("docker")
            .args(["swarm", "update", "--autolock=true"])
            .output()
            .await
            .map_err(|e| Error::Unexpected(format!("docker not found: {e}")))?;

        if !out.status.success() {
            return Err(Error::Unexpected(format!(
                "enabling the autolock: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }

        // The key is only available AFTER activation: asking before would return an
        // empty string, which would be filed in the vault as if the job were done.
        let out = tokio::process::Command::new("docker")
            .args(["swarm", "unlock-key", "-q"])
            .output()
            .await
            .map_err(|e| Error::Unexpected(format!("docker not found: {e}")))?;

        let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if key.is_empty() {
            return Err(Error::Unexpected("Swarm returned no unlock key".into()));
        }

        tracing::info!("autolock enabled");
        Ok(key)
    }

    async fn autolock_enabled(&self) -> Result<bool> {
        let s = self.docker.inspect_swarm().await?;
        Ok(s.spec
            .and_then(|sp| sp.encryption_config)
            .and_then(|e| e.auto_lock_managers)
            .unwrap_or(false))
    }

    async fn join_tokens(&self) -> Result<cluster::JoinTokens> {
        let s = self.docker.inspect_swarm().await?;

        let tokens = s
            .join_tokens
            .ok_or_else(|| Error::Unexpected("Swarm with no join tokens".into()))?;

        // The advertise address lives in the system info, not in the Swarm inspection.
        let info = self.docker.info().await?;
        // No address is an error, never a default: a join command naming 127.0.0.1
        // sends every node to itself.
        let addr = info
            .swarm
            .and_then(|s| s.node_addr)
            .filter(|a| !a.is_empty())
            .ok_or_else(|| {
                Error::Unexpected(
                    "Swarm states no address for this node: a join command would point \
                     nowhere"
                        .into(),
                )
            })?;

        Ok(cluster::JoinTokens {
            manager: tokens.manager.unwrap_or_default(),
            worker: tokens.worker.unwrap_or_default(),
            advertise_addr: format!("{addr}:2377"),
        })
    }

    async fn nodes(&self) -> Result<Vec<cluster::NodeInfo>> {
        let nodes = self.docker.list_nodes(None::<ListNodesOptions>).await?;

        Ok(nodes
            .into_iter()
            .map(|n| {
                let spec = n.spec.unwrap_or_default();
                let desc = n.description.unwrap_or_default();
                let status = n.status.unwrap_or_default();

                let role = match spec.role.map(|r| format!("{r:?}").to_lowercase()) {
                    Some(r) if r.contains("manager") => cluster::NodeRole::Manager,
                    _ => cluster::NodeRole::Worker,
                };

                cluster::NodeInfo {
                    id: n.id.unwrap_or_default(),
                    hostname: desc.hostname.unwrap_or_default(),
                    role,
                    status: status
                        .state
                        .map(|s| format!("{s:?}").to_lowercase())
                        .unwrap_or_else(|| "unknown".into()),
                    availability: spec
                        .availability
                        .map(|a| format!("{a:?}").to_lowercase())
                        .unwrap_or_else(|| "unknown".into()),
                    tier: spec.labels.as_ref().and_then(|l| l.get("tier").cloned()),
                    // 🔴 Read from the label, never guessed: Swarm does not know two
                    // VMs share hardware. `None` means undeclared, and that must be
                    // VISIBLE rather than let anyone assume the node is isolated.
                    failure_domain: spec
                        .labels
                        .as_ref()
                        .and_then(|l| l.get(cluster::LABEL_FAILURE_DOMAIN).cloned()),
                    data: spec
                        .labels
                        .iter()
                        .flatten()
                        .filter(|(_, v)| v.as_str() == "true")
                        .filter_map(|(k, _)| k.strip_prefix("hlb.data.").map(str::to_string))
                        .collect(),
                    ingress: spec.labels.as_ref().is_some_and(|l| {
                        l.get(hlb_types::manifest::INGRESS_NODE_LABEL)
                            .is_some_and(|v| v == "true")
                    }),
                    // Swarm has reported a manager's own address as 0.0.0.0; its
                    // manager address (`ip:2377`) is then where it really listens.
                    addr: status
                        .addr
                        .clone()
                        .filter(|a| !a.is_empty() && a != "0.0.0.0")
                        .or_else(|| {
                            n.manager_status
                                .as_ref()
                                .and_then(|m| m.addr.as_deref())
                                .and_then(|a| a.rsplit_once(':').map(|(h, _)| h.to_string()))
                        }),
                    is_leader: n.manager_status.and_then(|m| m.leader).unwrap_or(false),
                    memory_mb: desc
                        .resources
                        .and_then(|r| r.memory_bytes)
                        .map(|b| (b / 1_048_576) as u64),
                }
            })
            .collect())
    }

    async fn label_node(&self, node: &str, key: &str, value: &str) -> Result<()> {
        let n = self.docker.inspect_node(node).await?;
        let version = n
            .version
            .and_then(|v| v.index)
            .ok_or_else(|| Error::Unexpected("node with no version".into()))?;

        let mut spec = n.spec.unwrap_or_default();
        let mut labels = spec.labels.unwrap_or_default();
        labels.insert(key.to_string(), value.to_string());
        spec.labels = Some(labels);

        let opts = UpdateNodeOptionsBuilder::default()
            .version(version as i64)
            .build();
        self.docker.update_node(node, spec, opts).await?;

        tracing::info!(node, key, value, "label set");
        Ok(())
    }

    async fn set_node_availability(&self, node: &str, availability: &str) -> Result<()> {
        use bollard::models::NodeSpecAvailabilityEnum;

        // ⚠️ Parsed here rather than taken as a string: an unknown value would reach
        // Docker as an empty availability, which Swarm reads as "no change" — the call
        // would succeed and do nothing.
        let wanted = match availability {
            "active" => NodeSpecAvailabilityEnum::ACTIVE,
            "pause" => NodeSpecAvailabilityEnum::PAUSE,
            "drain" => NodeSpecAvailabilityEnum::DRAIN,
            other => {
                return Err(Error::Unexpected(format!(
                    "unknown availability \"{other}\": expected active, pause or drain"
                )))
            }
        };

        let n = self.docker.inspect_node(node).await?;
        let version = n
            .version
            .and_then(|v| v.index)
            .ok_or_else(|| Error::Unexpected("node with no version".into()))?;

        // 🔴 The WHOLE spec is sent back, with only the availability changed. Sending a
        // fresh spec would erase the labels — and the tier lives in a label, so every
        // placement constraint would stop matching and nothing would schedule.
        let mut spec = n.spec.unwrap_or_default();
        spec.availability = Some(wanted);

        let opts = UpdateNodeOptionsBuilder::default()
            .version(version as i64)
            .build();
        self.docker.update_node(node, spec, opts).await?;

        tracing::info!(node, availability, "availability set");
        Ok(())
    }

    async fn exec_in_service(&self, name: &str, cmd: &[String]) -> Result<ExecOutput> {
        // A service has no container: its tasks do. So we look for a running task and
        // enter ITS container.
        let mut filters = HashMap::new();
        filters.insert("service".to_string(), vec![name.to_string()]);
        filters.insert("desired-state".to_string(), vec!["running".to_string()]);

        let opts = ListTasksOptionsBuilder::default().filters(&filters).build();
        let tasks = self.docker.list_tasks(Some(opts)).await?;

        let (container, node) = tasks
            .iter()
            .filter(|t| {
                t.status
                    .as_ref()
                    .and_then(|s| s.state.as_ref())
                    .is_some_and(|s| format!("{s:?}").to_lowercase().contains("running"))
            })
            .find_map(|t| {
                let id = t
                    .status
                    .as_ref()?
                    .container_status
                    .as_ref()?
                    .container_id
                    .clone()?;
                Some((id, t.node_id.clone()))
            })
            .ok_or_else(|| {
                Error::Unexpected(format!(
                    "no running task for \"{name}\": cannot run the command"
                ))
            })?;

        // 🔴 The daemon `hlb` talks to has only its own node's containers: a task on
        // another node answered "no such container", read as the command failing.
        // There, a job on that node runs `docker exec` against its own daemon.
        if let (Some(node), Some(local)) = (node, self.local_node().await?) {
            if node != local {
                return self.exec_on_node(name, &node, &container, cmd).await;
            }
        }

        let exec = self
            .docker
            .create_exec(
                &container,
                CreateExecOptions {
                    cmd: Some(cmd.to_vec()),
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    ..Default::default()
                },
            )
            .await?;

        let mut stdout = String::new();
        let mut stderr = String::new();

        if let StartExecResults::Attached { mut output, .. } = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await?
        {
            use futures::StreamExt;
            while let Some(Ok(msg)) = output.next().await {
                match msg {
                    LogOutput::StdOut { message } => {
                        stdout.push_str(&String::from_utf8_lossy(&message));
                    }
                    LogOutput::StdErr { message } => {
                        stderr.push_str(&String::from_utf8_lossy(&message));
                    }
                    _ => {}
                }
            }
        }

        let info = self.docker.inspect_exec(&exec.id).await?;
        Ok(ExecOutput {
            exit_code: info.exit_code.unwrap_or(-1),
            stdout,
            stderr,
        })
    }

    async fn create_volume(&self, spec: &VolumeSpec) -> Result<VolumeInfo> {
        let name = spec.name.as_str();

        // A volume that already exists holds data: it is never recreated.
        if let Ok(v) = self.inspect_volume(name).await {
            tracing::debug!(name, "volume already present, kept");
            return Ok(VolumeInfo { existed: true, ..v });
        }

        let opts = CreateVolumeOptions {
            name: Some(name.to_string()),
            labels: Some(HashMap::from([(
                MANAGED_LABEL.to_string(),
                "true".to_string(),
            )])),
            // 🔴 For a bind or an NFS backing, Docker validates NOTHING here: the
            // options are recorded and the mount is attempted when a container first
            // uses the volume. A wrong path or an unreachable server therefore shows up
            // as a task that will not start, not as a failure of this call.
            driver_opts: spec.backing.driver_options(),
            ..Default::default()
        };

        let v = self.docker.create_volume(opts).await?;
        tracing::info!(
            name,
            mountpoint = %v.mountpoint,
            backing = %spec.backing.describe(),
            "volume created"
        );
        Ok(VolumeInfo {
            name: v.name,
            mountpoint: v.mountpoint,
            existed: false,
        })
    }

    async fn inspect_volume(&self, name: &str) -> Result<VolumeInfo> {
        let v = self
            .docker
            .inspect_volume(name)
            .await
            .map_err(|_| Error::NotFound(name.to_string()))?;
        Ok(VolumeInfo {
            name: v.name,
            mountpoint: v.mountpoint,
            existed: true,
        })
    }

    async fn status(&self, name: &str) -> Result<ServiceStatus> {
        let svc = self.inspect(name).await?;
        // By id, never by name: a service removed and created again under the same name
        // still lists the old one's tasks for a while, and a task of the removed
        // service still running counted toward the new one — an install reported
        // healthy over a service Swarm had left pending.
        let running = self
            .running_tasks(svc.id.as_deref().unwrap_or(name))
            .await?;
        Ok(Self::to_status(&svc, running))
    }

    async fn list(&self) -> Result<Vec<ServiceStatus>> {
        let mut filters = HashMap::new();
        filters.insert("label".to_string(), vec![format!("{MANAGED_LABEL}=true")]);
        let opts = ListServicesOptionsBuilder::default()
            .filters(&filters)
            .build();

        let services = self.docker.list_services(Some(opts)).await?;

        let mut out = Vec::with_capacity(services.len());
        for svc in services {
            let name = svc
                .spec
                .as_ref()
                .and_then(|s| s.name.clone())
                .unwrap_or_default();
            let running = self.running_tasks(&name).await.unwrap_or(0);
            out.push(Self::to_status(&svc, running));
        }
        Ok(out)
    }

    async fn remove(&self, name: &str) -> Result<()> {
        self.docker.delete_service(name).await.map_err(|e| match e {
            bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            } => Error::NotFound(name.to_string()),
            other => Error::Docker(other),
        })
    }

    async fn tasks(&self, service: Option<&str>) -> Result<Vec<TaskInfo>> {
        self.read_tasks(service).await
    }

    async fn running_env(&self, name: &str) -> Result<Option<Vec<String>>> {
        let mut filters = HashMap::new();
        filters.insert("service".to_string(), vec![name.to_string()]);
        filters.insert("desired-state".to_string(), vec!["running".to_string()]);
        let opts = ListTasksOptionsBuilder::default().filters(&filters).build();
        let tasks = self.docker.list_tasks(Some(opts)).await?;
        // A task starting under a new spec is not yet what serves: the running one is.
        Ok(tasks
            .iter()
            .filter(|t| {
                t.status
                    .as_ref()
                    .and_then(|s| s.state)
                    .is_some_and(|s| format!("{s:?}").eq_ignore_ascii_case("running"))
            })
            .find_map(|t| t.spec.as_ref()?.container_spec.as_ref())
            .map(|c| c.env.clone().unwrap_or_default()))
    }

    async fn local_node(&self) -> Result<Option<String>> {
        Ok(self
            .docker
            .info()
            .await?
            .swarm
            .and_then(|s| s.node_id)
            .filter(|id| !id.is_empty()))
    }

    async fn logs(&self, service: &str, rows: u32) -> Result<Vec<LogLine>> {
        // 🔴 Bounded. A chatty service left unbounded would fill the controller's
        // memory - and the controller is what would fall over, not the service being
        // diagnosed.
        const CEILING: u32 = 2_000;
        let n = rows.clamp(1, CEILING);

        // 🔴 Through the CLI: bollard 0.19 has no SERVICE logs. Its `logs` is the
        // container endpoint, which a service name answers with "no such container" —
        // swallowed by the one caller, so every failed job's reason read empty: "Caddy
        // refused the new configuration: " and nothing, a restic job "exit (1)". The
        // service endpoint is also the only one reaching a task on another node.
        let out = tokio::process::Command::new("docker")
            .args(["service", "logs", "--raw", "--timestamps", "--tail"])
            .arg(n.to_string())
            .arg(service)
            .output()
            .await
            .map_err(|e| Error::Unexpected(format!("docker not found: {e}")))?;
        if !out.status.success() && out.stdout.is_empty() {
            return Err(Error::Unexpected(format!(
                "logs of {service}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        // The task's stdout comes on the CLI's stdout, its stderr on the CLI's.
        let mut lines = Vec::new();
        for (error, stream) in [(false, &out.stdout), (true, &out.stderr)] {
            // ⚠️ `from_utf8_lossy`: an application log sometimes contains bytes that
            // are not UTF-8 (truncated ANSI colours, binary). Failing would withhold
            // the WHOLE log because of one line.
            for text in String::from_utf8_lossy(stream).lines() {
                // Docker prefixes each line with its RFC 3339 timestamp when
                // `--timestamps` is on.
                let (at, line) = match text.split_once(' ') {
                    Some((h, remaining)) => (unix_timestamp(h), remaining.to_string()),
                    None => (None, text.to_string()),
                };
                lines.push(LogLine { at, error, line });
            }
        }
        // Two streams read one after the other: put back in time order.
        lines.sort_by_key(|l| l.at);
        Ok(lines)
    }

    async fn wait_healthy(&self, name: &str, timeout_secs: u64) -> Result<ServiceStatus> {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(timeout_secs);
        let mut last = self.status(name).await?;

        while tokio::time::Instant::now() < deadline {
            last = self.status(name).await?;

            // No point waiting out a timeout when Swarm has already rolled back.
            if last.update_state.is_some_and(|s| s.is_failure()) {
                break;
            }
            if last.is_converged() && last.rollout_concluded(&self.read_tasks(Some(name)).await?) {
                return Ok(last);
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        Err(Error::HealthTimeout {
            service: name.to_string(),
            timeout_secs,
            running: last.running_replicas,
            desired: last.desired_replicas,
            why: self
                .read_tasks(Some(name))
                .await
                .ok()
                .and_then(|t| crate::why_not_running(&t)),
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn two_runs_of_one_job_never_share_a_name() {
        // 🔴 Found by review: a backup and a restore of one app were both
        // `hlb-backup-<app>`, and each run deleted the service of that name first.
        let base = "hlb-backup-immich-machine-learning";
        let (a, b) = (super::job_name(base), super::job_name(base));
        assert_ne!(a, b);
        for n in [&a, &b] {
            assert!(n.starts_with(base), "{n}");
            assert!(super::is_run_of(n, base), "{n}");
        }
        // Another job's runs are not this one's, even sharing its beginning.
        let other = super::job_name("hlb-backup-immich");
        assert!(!super::is_run_of(&a, "hlb-backup-immich"), "{a}");
        assert!(super::is_run_of(&other, "hlb-backup-immich"));
        assert!(super::is_run_of("hlb-backup-immich", "hlb-backup-immich"));
        // Swarm names a service in 63 characters at most.
        let long = super::job_name(&"x".repeat(80));
        assert!(long.len() <= 63, "{} characters", long.len());
        assert!(super::is_run_of(&long, &"x".repeat(80)));
    }

    #[test]
    fn a_service_keeping_data_on_its_node_is_never_run_twice_over_it() {
        use bollard::models::ServiceSpecUpdateConfigOrderEnum as Order;
        let order = |spec: &ServiceSpec| {
            SwarmOrchestrator::to_bollard(spec)
                .update_config
                .and_then(|u| u.order)
        };
        let stateless = ServiceSpec::new("whoami", "traefik/whoami:v1.10");
        assert_eq!(order(&stateless), Some(Order::START_FIRST));
        let postgres = ServiceSpec::new("postgres", "postgres:17").mount("postgres-data", "/data");
        assert_eq!(order(&postgres), Some(Order::STOP_FIRST));
        // On NFS the data follows the service: no reason to stop first.
        let media = ServiceSpec::new("jellyfin", "jellyfin/jellyfin:10").mount_backed(
            "jellyfin-media",
            "/media",
            VolumeBacking::Nfs {
                server: "10.0.0.2".into(),
                export: "/tank/apps/jellyfin/media".into(),
            },
        );
        assert_eq!(order(&media), Some(Order::START_FIRST));
    }

    #[test]
    fn a_tmpfs_reaches_swarm_open_to_the_container_s_user() {
        let mut spec = ServiceSpec::new("fluxer-api", "fluxer-api:1");
        spec.hardening.tmpfs = vec!["/run/fluxer".into()];
        let created = SwarmOrchestrator::to_bollard(&spec);
        let mounts = created
            .task_template
            .and_then(|t| t.container_spec)
            .and_then(|c| c.mounts)
            .expect("a mount");
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].typ, Some(MountTypeEnum::TMPFS));
        assert_eq!(mounts[0].target.as_deref(), Some("/run/fluxer"));
        assert_eq!(
            mounts[0].tmpfs_options.as_ref().and_then(|o| o.mode),
            Some(0o1777),
            "root's 0755 shuts out an image's own user"
        );
    }

    #[test]
    fn a_service_holding_a_port_of_its_node_stops_before_its_next_task() {
        // 🔴 Started first, LiveKit's new task waited "host-mode port already in use"
        // on the one ingress node, and the update never ended (the lab, 2026-10-27).
        use bollard::models::ServiceSpecUpdateConfigOrderEnum as Order;
        let mut livekit = ServiceSpec::new("fluxer-livekit", "livekit/livekit-server:v1");
        livekit.hardening.published_ports = vec![hlb_types::manifest::PublishedPort {
            port: 7882,
            protocol: hlb_types::manifest::Protocol::Udp,
        }];
        let created = SwarmOrchestrator::to_bollard(&livekit);
        assert_eq!(
            created.update_config.as_ref().and_then(|u| u.order),
            Some(Order::STOP_FIRST)
        );
        assert!(
            super::stops_first(&created),
            "read back from Swarm, an update keeps the order"
        );
        let stateless = SwarmOrchestrator::to_bollard(&ServiceSpec::new("whoami", "whoami:1"));
        assert!(!super::stops_first(&stateless));
    }

    #[test]
    fn a_service_s_memory_reaches_swarm_as_a_reservation_and_a_limit() {
        let mut spec = ServiceSpec::new("gitea", "gitea/gitea:1.27");
        assert!(SwarmOrchestrator::to_bollard(&spec)
            .task_template
            .and_then(|t| t.resources)
            .is_none());
        spec.memory = Some(hlb_types::Memory {
            reserve: hlb_types::manifest::Bytes::try_from("256M".to_string()).expect("size"),
            limit: hlb_types::manifest::Bytes::try_from("1G".to_string()).expect("size"),
        });
        let r = SwarmOrchestrator::to_bollard(&spec)
            .task_template
            .and_then(|t| t.resources)
            .expect("resources");
        assert_eq!(
            r.reservations.and_then(|x| x.memory_bytes),
            Some(256 * 1024 * 1024)
        );
        assert_eq!(
            r.limits.and_then(|x| x.memory_bytes),
            Some(1024 * 1024 * 1024)
        );
    }

    #[test]
    fn a_registry_is_read_from_the_image_reference() {
        assert_eq!(
            registry_host("ghcr.io/turi-industries/hlb-agent:0.1.0"),
            Some("ghcr.io")
        );
        assert_eq!(
            registry_host("registry.local:5000/x:1"),
            Some("registry.local:5000")
        );
        // Docker Hub: no host segment, no credentials looked up.
        assert_eq!(registry_host("grafana/grafana:11"), None);
        assert_eq!(registry_host("alpine:3"), None);
    }

    use super::*;

    #[test]
    fn docker_timestamps_are_read_or_refused_never_guessed() {
        // 🔴 A half-read timestamp would put a log line in 1970, and you would go
        // looking for a clock problem on the node.
        assert_eq!(unix_timestamp("1970-01-01T00:00:00Z"), Some(0));
        // Reference values, computed independently (not derived from the code tested).
        assert_eq!(
            unix_timestamp("2026-08-18T10:16:04.123456789Z"),
            Some(1_787_048_164)
        );
        // With no fraction and no "Z": Docker varies between versions.
        assert_eq!(unix_timestamp("2026-08-18T10:16:04"), Some(1_787_048_164));

        // A century leap year: 2000 is a leap year, 1900 is not. A naive division by
        // 4 gets this wrong.
        assert_eq!(unix_timestamp("2000-03-01T00:00:00Z"), Some(951_868_800));

        for bad in [
            "",
            "not a date",
            "2026-08-18",
            "2026/08/18T10:16:04Z",
            "T10:16:04",
        ] {
            assert_eq!(unix_timestamp(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_timestamp_round_trips_against_a_known_pair() {
        // A cross-check: 86,400 s after the epoch is 2 January 1970.
        assert_eq!(unix_timestamp("1970-01-02T00:00:00Z"), Some(86_400));
        // And a year later, 1971: 365 days (1970 is not a leap year).
        assert_eq!(unix_timestamp("1971-01-01T00:00:00Z"), Some(31_536_000));
    }
}
