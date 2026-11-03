use super::*;

#[derive(Debug, PartialEq, Eq)]
pub enum NextPoll {
    Pending,
    Ready { status: u32, result: Vec<u8> },
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn complete(_: Handle, _: *const v22::Completion, _: *mut ErrorBuffer) -> u32 {
        v22::INVALID
    }

    unsafe extern "C" fn get(_: Handle, _: Handle, _: Handle, _: Bytes, _: *mut v22::Buffer, _: *mut ErrorBuffer) -> u32 {
        v22::INVALID
    }

    unsafe extern "C" fn set(_: Handle, _: Handle, _: Handle, _: Bytes, _: Bytes, _: *mut ErrorBuffer) -> u32 {
        v22::INVALID
    }

    unsafe extern "C" fn start(instance: Handle, _: Handle, output: *mut Handle, _: *mut ErrorBuffer) -> u32 {
        unsafe { output.write(if instance.slot == 0 { Handle::NONE } else { instance }) };
        abi::OK
    }

    unsafe extern "C" fn task(instance: Handle, _: Handle, _: Handle, _: *mut ErrorBuffer) -> u32 {
        if instance.slot == 20 { v22::REQUEST_CANCELLED } else { abi::OK }
    }

    unsafe extern "C" fn poll(instance: Handle, _: Handle, _: Handle, output: *mut v23::NextOutput, error: *mut ErrorBuffer) -> u32 {
        let output = unsafe { &mut *output };
        match instance.slot {
            0 => {}
            1..=3 => {
                unsafe { output.result.data.write(b'x') };
                output.result.len = 1;
                output.status = instance.slot - 1;
            }
            10 => output.header.major = 3,
            11 => output.header.struct_size = u32::MAX,
            12 => output.header.minor = 2,
            13 => output.reserved = 1,
            14 => output.result.data = ptr::null_mut(),
            15 => output.result.capacity -= 1,
            16 => output.result.len = output.result.capacity + 1,
            17 => output.status = 99,
            18 => output.result.len = 1,
            19 => unsafe { (*error).capacity += 1 },
            _ => return v22::INVALID,
        }
        abi::OK
    }

    fn host(mode: u32) -> Host {
        Host {
            instance: Handle { epoch: 1, slot: mode, generation: 1 },
            complete, state_get: get, state_set: set,
            continuation: Some(v23::ContinuationApi {
                header: v23::header::<v23::ContinuationApi>(),
                start: Some(start), poll: Some(poll), cancel: Some(task), release: Some(task), reserved: 0,
            }),
        }
    }

    #[test]
    fn poll_rejects_mutated_caller_storage_and_invalid_protocol_fields() {
        assert_eq!(host(0).next_poll(Handle::NONE, Handle::NONE).unwrap(), NextPoll::Pending);
        for mode in 1..=3 {
            assert_eq!(host(mode).next_poll(Handle::NONE, Handle::NONE).unwrap(),
                NextPoll::Ready { status: mode - 1, result: b"x".to_vec() });
        }
        for mode in 10..=19 {
            assert_eq!(host(mode).next_poll(Handle::NONE, Handle::NONE).unwrap_err().code, v22::INVALID, "mode {mode}");
        }
    }

    #[test]
    fn start_requires_a_task_and_task_errors_are_preserved() {
        assert_eq!(host(0).next_start(Handle::NONE).unwrap_err().code, v22::INVALID);
        assert_eq!(host(1).next_start(Handle::NONE).unwrap(), host(1).instance);
        assert_eq!(host(20).next_cancel(Handle::NONE, Handle::NONE).unwrap_err().code, v22::REQUEST_CANCELLED);
        assert_eq!(host(20).next_release(Handle::NONE, Handle::NONE).unwrap_err().code, v22::REQUEST_CANCELLED);
        let mut legacy = host(1);
        legacy.continuation = None;
        assert_eq!(legacy.next_start(Handle::NONE).unwrap_err().code, v22::INVALID);
    }
}

impl Host {
    fn next_api(self) -> Result<v23::ContinuationApi, Error> {
        self.continuation.ok_or_else(|| Error { code: v22::INVALID, message: "ABI 2.3 continuation unavailable".into() })
    }

    pub fn next_start(self, request: Handle) -> Result<Handle, Error> {
        let api = self.next_api()?;
        let mut task = Handle::NONE;
        call(|error| unsafe { (api.start.expect("negotiated start"))(self.instance, request, &mut task, error) })?;
        if task == Handle::NONE {
            return Err(Error { code: v22::INVALID, message: "null next task".into() });
        }
        Ok(task)
    }

    pub fn next_poll(self, request: Handle, task: Handle) -> Result<NextPoll, Error> {
        let api = self.next_api()?;
        let mut storage = vec![0; v22::MAX_RESULT];
        let mut output = v23::NextOutput {
            header: v23::header::<v23::NextOutput>(), status: v23::PENDING, reserved: 0,
            result: v22::Buffer { data: storage.as_mut_ptr(), capacity: storage.len() as u64, len: 0 },
        };
        call(|error| unsafe { (api.poll.expect("negotiated poll"))(self.instance, request, task, &mut output, error) })?;
        if output.header.struct_size != size_of::<v23::NextOutput>() as u32
            || output.header.major != 2 || output.header.minor != 3 || output.reserved != 0
            || output.result.data != storage.as_mut_ptr() || output.result.capacity != storage.len() as u64
            || output.result.len > output.result.capacity
            || ![v22::SUCCEEDED, v22::FAILED, v22::CANCELLED, v23::PENDING].contains(&output.status)
            || (output.status == v23::PENDING && output.result.len != 0)
        {
            return Err(Error { code: v22::INVALID, message: "invalid next output".into() });
        }
        storage.truncate(output.result.len as usize);
        Ok(if output.status == v23::PENDING { NextPoll::Pending } else { NextPoll::Ready { status: output.status, result: storage } })
    }

    pub fn next_cancel(self, request: Handle, task: Handle) -> Result<(), Error> {
        let api = self.next_api()?;
        call(|error| unsafe { (api.cancel.expect("negotiated cancel"))(self.instance, request, task, error) })
    }

    pub fn next_release(self, request: Handle, task: Handle) -> Result<(), Error> {
        let api = self.next_api()?;
        call(|error| unsafe { (api.release.expect("negotiated release"))(self.instance, request, task, error) })
    }
}
