// Package daemon spawns the hush agent as a detached background process
// and hands it the decrypted identity out-of-band, never through disk.
//
// Unix: the identity travels over an inherited pipe (fd 3) and the child
// detaches by re-exec with no controlling terminal.
//
// Windows: the child is created outside the caller's job object (so it
// survives the launching terminal, which Windows Terminal and VS Code
// run with KILL_ON_JOB_CLOSE) via WMI Win32_Process.Create. A
// WMI-created process inherits none of the caller's handles, so the
// identity travels over a short-lived AF_UNIX handoff socket instead.
// It also inherits only the user's base environment, so a small launcher
// script re-applies HUSH_* overrides and the handoff control vars.
package daemon

// ChildEnvVar marks a re-exec'd process as an agent child. Spawn sets it
// on the child; the child's main() checks it to route into agent mode.
const ChildEnvVar = "HUSH_AGENT_CHILD"

// identitySockEnv names the AF_UNIX handoff socket on Windows. It is an
// internal contract between Spawn and ReadIdentity.
const identitySockEnv = "HUSH_IDENTITY_SOCK"
