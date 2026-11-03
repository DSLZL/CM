use super::*;
use std::sync::{Arc, Mutex};

struct Queue {
    next: u64,
    pending: Option<u64>,
}
struct Actor {
    scope: runtime::UiScope,
    thread: std::thread::ThreadId,
    queue: Mutex<Queue>,
}

pub struct UiOwner {
    actor: Arc<Actor>,
}
pub struct UiWork {
    actor: Arc<Actor>,
    id: u64,
    request: Option<runtime::RequestFuture>,
    handed_off: bool,
}
pub struct UiCompletion {
    actor: Arc<Actor>,
    id: u64,
    result: Option<Result<String, LoadError>>,
}

impl std::fmt::Debug for UiCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CmUiCompletion")
            .field("id", &self.id)
            .finish()
    }
}

fn clear(actor: &Actor, id: u64) {
    if let Ok(mut queue) = actor.queue.lock()
        && queue.pending == Some(id)
    {
        queue.pending = None;
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Notice {
    version: u32,
    notice: String,
}

fn notice(bytes: &[u8]) -> Result<String, LoadError> {
    let result: Notice = serde_json::from_slice(bytes).map_err(|_| error("invalid UI notice"))?;
    if result.version != 1
        || result.notice.len() > 8192
        || result
            .notice
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\t'))
    {
        return Err(error("UI notice version/size/control character rejected"));
    }
    Ok(result.notice)
}

impl UiOwner {
    /// Construct only in the actual UI actor, never in a native/background callback.
    pub fn new() -> Result<Self, LoadError> {
        Ok(Self {
            actor: Arc::new(Actor {
                scope: runtime::UiScope::new()?,
                thread: std::thread::current().id(),
                queue: Mutex::new(Queue {
                    next: 1,
                    pending: None,
                }),
            }),
        })
    }

    fn check_thread(&self) -> Result<(), LoadError> {
        if self.actor.thread != std::thread::current().id() {
            return Err(error("UI apply on wrong thread"));
        }
        self.actor.scope.check()
    }

    pub fn begin(
        &self,
        graph: &Graph,
        name: &str,
        argument: Option<&str>,
    ) -> Result<UiWork, LoadError> {
        self.check_thread()?;
        let command = graph
            .get(Section::Tui, name)
            .ok_or_else(|| error("unknown UI command"))?;
        let input = input(command, argument)?;
        let contribution = binding(command)?;
        let id = {
            let mut queue = self
                .actor
                .queue
                .lock()
                .map_err(|_| error("poisoned UI command queue"))?;
            if queue.pending.is_some() {
                return Err(error("UI command already pending"));
            }
            let id = queue.next;
            queue.next = id
                .checked_add(1)
                .ok_or_else(|| error("UI command identity exhausted"))?;
            queue.pending = Some(id);
            id
        };
        match runtime::dispatch_ui(&self.actor.scope, &contribution, &input) {
            Ok(request) => Ok(UiWork {
                actor: Arc::clone(&self.actor),
                id,
                request: Some(request),
                handed_off: false,
            }),
            Err(error) => {
                clear(&self.actor, id);
                Err(error)
            }
        }
    }

    /// Returns text only after owner/thread/lifetime checks; the caller displays it now.
    pub fn apply(&self, completion: &mut UiCompletion) -> Result<String, LoadError> {
        self.check_thread()?;
        if !Arc::ptr_eq(&self.actor, &completion.actor) {
            return Err(error("stale UI command owner"));
        }
        let mut queue = self
            .actor
            .queue
            .lock()
            .map_err(|_| error("poisoned UI command queue"))?;
        if queue.pending != Some(completion.id) {
            return Err(error("stale/duplicate UI completion"));
        }
        let result = completion
            .result
            .take()
            .ok_or_else(|| error("UI completion already consumed"))?;
        queue.pending = None;
        crate::event(
            "tui-command-applied",
            json!({"id": completion.id, "ok": result.is_ok()}),
        );
        result
    }
}

impl Drop for UiOwner {
    fn drop(&mut self) {
        self.actor.scope.close();
    }
}

impl UiWork {
    pub async fn run(mut self) -> UiCompletion {
        let result = match self.request.take().expect("accepted UI work").await {
            Ok(bytes) => notice(&bytes),
            Err(error) => Err(error),
        };
        self.handed_off = true;
        UiCompletion {
            actor: Arc::clone(&self.actor),
            id: self.id,
            result: Some(result),
        }
    }
}

impl Drop for UiWork {
    fn drop(&mut self) {
        if !self.handed_off {
            clear(&self.actor, self.id);
        }
    }
}
impl Drop for UiCompletion {
    fn drop(&mut self) {
        clear(&self.actor, self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notices_cannot_smuggle_commands_or_terminal_control() {
        for bytes in [
            br#"{"version":1,"notice":"ok","send":"x"}"#.as_slice(),
            br#"{"version":2,"notice":"ok"}"#,
            br#"{"version":1,"notice":"\u001b[2J"}"#,
        ] {
            assert!(notice(bytes).is_err());
        }
        assert_eq!(
            notice(br#"{"version":1,"notice":"hello\nworld"}"#).unwrap(),
            "hello\nworld"
        );
    }
}
