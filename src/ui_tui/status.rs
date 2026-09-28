use super::*;
pub struct Observer {
    pub value: Value,
    operation: Option<Operation>,
    started: Instant,
    next: Instant,
    timed_out: bool,
}
impl Observer {
    pub fn new() -> Self {
        Self {
            value: json!({"state":"unknown","label":"Проверяем состояние"}),
            operation: None,
            started: Instant::now(),
            next: Instant::now(),
            timed_out: false,
        }
    }
    pub fn refresh(&mut self) {
        self.next = Instant::now();
    }
    pub fn tick(&mut self) -> Result<bool> {
        if self.operation.is_none() && Instant::now() >= self.next {
            self.operation = Some(Operation::spawn(&mut job::command("status")?)?);
            self.started = Instant::now();
            self.next = self.started + Duration::from_secs(3);
            self.timed_out = false;
        }
        let Some(op) = &mut self.operation else {
            return Ok(false);
        };
        if self.started.elapsed() >= Duration::from_secs(5) && !self.timed_out {
            self.timed_out = true;
            op.cancel(CancelSignal::Terminate);
            self.value = json!({"state":"unknown","label":"Состояние не получено: превышено время ожидания"});
            return Ok(true);
        }
        let value = match op.poll() {
            Ok(update) => match update.outcome {
                None => return Ok(false),
                Some(o) if o.status == ActionStatus::Completed && !self.timed_out => o.data,
                Some(_) => json!({"state":"unknown","label":"Не удалось определить состояние"}),
            },
            Err(e) => {
                json!({"state":"unknown","label":"Не удалось определить состояние","detail":e.message})
            }
        };
        self.operation = None;
        self.next = Instant::now() + Duration::from_secs(3);
        let changed = value != self.value;
        self.value = value;
        Ok(changed)
    }
    pub fn stop(&mut self) {
        if let Some(op) = &mut self.operation {
            op.cancel(CancelSignal::Terminate);
        }
        self.operation = None;
    }
}
