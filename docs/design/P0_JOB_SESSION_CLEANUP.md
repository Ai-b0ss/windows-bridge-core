# Owned non-detached terminal job cleanup

Windows 10+/Server2016+ non-detached `start_process` uses a private, unnamed
kill-on-close Job Object. JOB_LIST binds the process during CreateProcessW;
only the three binary stdio handles are inherited through HANDLE_LIST. The
initial thread resumes after parent pipe setup. There is no create-then-assign
interval, breakaway flag, process-name cleanup, taskkill or uncontained fallback.
Failure to configure the required attributes refuses the launch.

`force_terminate` can clean the job even after its root shell has already exited.
It checks job accounting until no active members remain before returning
`termination_scope=owned_job_members` and `descendant_cleanup_verified=true`.
The original root exit status remains its actual status. Detached sessions
continue to use their existing restart-surviving, birth-bound root process path;
their descendant cleanup is still unverified. These are distinct guarantees.

Jobs cover normal CreateProcess descendants and nested child jobs. External
brokers, services and WMI-created processes are not necessarily job members;
`external_broker_children_verified=false` is explicit. This is not a hostile
same-account sandbox or a claim about every crash micro-step inside Windows.
No existing home process is redeployed or attached to by this source change.

The unit suite includes real Windows tests for binary stdin/stdout/stderr,
Unicode environment/argument quoting, exit37, descendants surviving root exit,
foreign-process preservation, and kill-on-close after hard supervisor death.
Mocked negative tests ensure unsupported JOB_LIST refuses CreateProcess.
Both ordinary source CI and the exact-source installed candidate gate must pass.

Primary contracts:

- [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Creation attributes, including JOB_LIST and HANDLE_LIST](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute.md)
- [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [TerminateJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-terminatejobobject)
