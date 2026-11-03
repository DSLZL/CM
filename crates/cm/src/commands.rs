//! One immutable metadata graph; no native entry is needed to inspect commands.
use std::collections::BTreeSet;
use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use crate::{LoadError, config, loader, manifest, runtime, runtime_plan};

mod ui;
pub use ui::{UiCompletion, UiOwner, UiWork};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Section { Cli, Tui }

impl Section {
    fn kind(self) -> runtime::Kind {
        match self { Self::Cli => runtime::Kind::CliCommand, Self::Tui => runtime::Kind::TuiCommand }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Input { None, Optional, Required }

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Declaration {
    pub id: String,
    pub name: String,
    pub help: String,
    pub input: Input,
    pub section: Section,
    pub route: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata { pub version: u32, pub entries: Vec<Declaration> }

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Command { pub owner: String, pub spec: Declaration }

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Graph { pub plan_sha256: String, entries: Vec<Command> }

fn error(message: &str) -> LoadError { LoadError::native("command", message) }

pub(crate) fn validate_manifest(manifest: &manifest::BinaryManifest) -> Result<(), String> {
    let commands: Vec<_> = manifest.contributions.iter().filter(|item| matches!(item.kind, loader::Kind::CliCommand | loader::Kind::TuiCommand)).collect();
    let Some(metadata) = &manifest.commands else {
        return if commands.is_empty() { Ok(()) } else { Err("commands: missing metadata".into()) };
    };
    if manifest.compat.abi_major != 2 || manifest.compat.abi_minor_min != 3 || metadata.version != 1
        || metadata.entries.is_empty() || metadata.entries.len() > 32 || metadata.entries.len() != commands.len()
    { return Err("commands: invalid ABI/version/count".into()); }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut routes = BTreeSet::new();
    for entry in &metadata.entries {
        let kind = match entry.section { Section::Cli => loader::Kind::CliCommand, Section::Tui => loader::Kind::TuiCommand };
        if !runtime::valid_name(&manifest.id, &entry.name) || entry.help.is_empty() || entry.help.len() > 256
            || entry.help.chars().any(char::is_control) || entry.route == 0
            || !ids.insert(entry.id.clone()) || !names.insert((entry.section, entry.name.clone())) || !routes.insert(entry.route)
            || !commands.iter().any(|item| item.id == entry.id && item.resource == entry.name && item.kind == kind)
        { return Err("commands: invalid/duplicate name, help, route or contribution binding".into()); }
    }
    Ok(())
}

pub(crate) fn check_route(manifest: &loader::Manifest, contribution: &loader::Contribution, route: u64) -> Result<(), LoadError> {
    if !matches!(contribution.kind, loader::Kind::CliCommand | loader::Kind::TuiCommand) { return Ok(()); }
    let declared = manifest.binary_manifest.as_ref().and_then(|manifest| manifest.commands.as_ref())
        .and_then(|metadata| metadata.entries.iter().find(|entry| entry.id == contribution.id));
    if declared.is_none_or(|entry| entry.route != route) {
        return Err(runtime::registration_error(&manifest.id, &contribution.id, "actual command route differs from frozen metadata"));
    }
    Ok(())
}

impl Graph {
    pub fn from_plan(plan: &runtime_plan::RuntimePlan) -> Result<Self, LoadError> {
        let mut entries = Vec::new();
        let mut names = BTreeSet::new();
        for (owner, module) in &plan.mods {
            if let Some(metadata) = module.metadata.as_ref().and_then(|value| value.get("commands")) {
                let metadata: Metadata = serde_json::from_value(metadata.clone()).map_err(|_| error("invalid planned command metadata"))?;
                for spec in metadata.entries {
                    if !names.insert((spec.section, spec.name.clone())) { return Err(error("duplicate planned command")); }
                    entries.push(Command { owner: owner.clone(), spec });
                }
            }
        }
        entries.sort_by(|a, b| (&a.spec.section, &a.spec.name).cmp(&(&b.spec.section, &b.spec.name)));
        Ok(Self { plan_sha256: plan.sha256(), entries })
    }

    pub fn prepare(home: &Path, options: &config::Options) -> Result<Self, LoadError> {
        let prepared = runtime_plan::prepare_options(home, options)?;
        prepared.revalidate()?;
        Self::from_plan(prepared.plan())
    }

    pub fn entries(&self, section: Section) -> impl Iterator<Item = &Command> { self.entries.iter().filter(move |item| item.spec.section == section) }
    pub fn get(&self, section: Section, name: &str) -> Option<&Command> { self.entries(section).find(|entry| entry.spec.name == name) }

    /// Called with names from the actual Host command registry before insertion.
    pub fn check_names(&self, section: Section, occupied: impl IntoIterator<Item = impl AsRef<str>>) -> Result<(), LoadError> {
        let occupied: BTreeSet<_> = occupied.into_iter().map(|name| name.as_ref().to_owned()).collect();
        for command in self.entries(section) {
            if occupied.contains(&command.spec.name) {
                let mut error = LoadError::input("command_name_collision", &command.owner, "command collides with an actual Host builtin/dynamic command");
                error.contribution = Some(command.spec.id.clone());
                error.resource = Some(command.spec.name.clone());
                return Err(error);
            }
        }
        Ok(())
    }
}

pub fn configured_graph() -> Result<Graph, LoadError> {
    static GRAPH: std::sync::OnceLock<Result<Graph, LoadError>> = std::sync::OnceLock::new();
    if let Some(runtime) = crate::RUNTIME.get() {
        let runtime = runtime.as_ref().map_err(Clone::clone)?;
        let state = runtime.state.lock().map_err(|_| error("poisoned command graph"))?;
        let registration = state.registration.as_ref().ok_or_else(|| error("runtime closed"))?;
        return GRAPH.get_or_init(|| Graph::from_plan(&registration.plan)).clone();
    }
    if let Some(pending) = crate::PENDING_TUI.get() {
        let pending = pending.lock().map_err(|_| error("poisoned pending command graph"))?;
        if let Some(prepared) = pending.as_ref() { return GRAPH.get_or_init(|| Graph::from_plan(prepared.plan())).clone(); }
    }
    Ok(Graph::default())
}

fn binding(command: &Command) -> Result<runtime::Contribution, LoadError> {
    runtime::ordered_contributions(command.spec.section.kind())?.into_iter()
        .find(|item| item.owner == command.owner && item.id == command.spec.id && item.name == command.spec.name && item.route == command.spec.route)
        .ok_or_else(|| runtime::registration_error(&command.owner, &command.spec.id, "actual command binding differs from graph"))
}

fn input(command: &Command, value: Option<&str>) -> Result<Vec<u8>, LoadError> {
    if value.is_some_and(|value| value.len() > 8192)
        || (command.spec.input == Input::None && value.is_some())
        || (command.spec.input == Input::Required && value.is_none())
    { return Err(error("command requires its declared single UTF-8 argument (maximum 8192 bytes)")); }
    Ok(json!({"version": 1, "input": value}).to_string().into_bytes())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Output { version: u32, text: String }

pub async fn run(home: &Path, options: &config::Options, graph: &Graph, name: &str, argument: Option<&str>) -> Result<Value, LoadError> {
    let command = graph.get(Section::Cli, name).ok_or_else(|| error("unknown CLI command"))?;
    let input = input(command, argument)?;
    crate::state::prepare_environment(home)?;
    let prepared = runtime_plan::prepare_options(home, options)?;
    if &Graph::from_plan(prepared.plan())? != graph { return Err(LoadError::input("input_drift", &command.owner, "command graph changed before execution")); }
    let guard = crate::initialize_command(prepared)?;
    let scope = runtime::UiScope::new()?;
    let result = runtime::dispatch_ui(&scope, &binding(command)?, &input)?.await?;
    scope.check()?;
    let result: Output = serde_json::from_slice(&result).map_err(|_| error("invalid CLI command result"))?;
    if result.version != 1 || result.text.len() > 64 * 1024 { return Err(error("invalid CLI result version/size")); }
    drop(scope);
    guard.finish()?;
    Ok(json!({"command": name, "text": result.text}))
}
